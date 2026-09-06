"""
Autenticacao para a Shopee Open Platform API v2.

Referencia oficial: https://open.shopee.com/documents (exige login de
parceiro para acessar a doc completa). Confirme os valores abaixo contra a
doc oficial antes de ir pra producao - confirmados em 08/2026:
  - access_token valido por 4 horas
  - refresh_token valido por 30 dias
  - cada refresh tambem ROTACIONA o refresh_token (assim como no Mercado Livre)

Como funciona a assinatura (sign) de cada chamada:
  base_string = f"{partner_id}{path}{timestamp}"                     # endpoints publicos
  base_string = f"{partner_id}{path}{timestamp}{access_token}{shop_id}"  # endpoints de loja
  sign = HMAC_SHA256(base_string, partner_key).hexdigest()

Pontos de seguranca implementados aqui:
  - partner_key nunca sai do processo local (usado so para gerar o HMAC).
  - hmac.compare_digest ao validar assinaturas recebidas (webhooks), para
    evitar timing attacks - ver `verify_push_signature`.
  - timestamp usado no sign precisa do relogio da maquina sincronizado (NTP);
    um relogio dessincronizado faz a Shopee rejeitar a assinatura.
  - "state" aleatorio no fluxo de autorizacao para mitigar CSRF, do mesmo
    jeito que no modulo mercadolivre/auth.py.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import requests

from .exceptions import ShopeeAuthError

HOSTS = {
    "live": "https://partner.shopeemobile.com",
    "test": "https://partner.test-stable.shopeemobile.com",
}
AUTH_PATH = "/api/v2/shop/auth_partner"
TOKEN_GET_PATH = "/api/v2/auth/token/get"
TOKEN_REFRESH_PATH = "/api/v2/auth/access_token/get"
REQUEST_TIMEOUT = 15


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def _sign(partner_key: str, base_string: str) -> str:
    return hmac.new(
        partner_key.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_push_signature(raw_body: bytes, received_sign: str, partner_key: str, url: str) -> bool:
    """
    Valida a assinatura de um webhook/push notification recebido da Shopee.
    A Shopee assina `url + "|" + body` com o partner_key e manda o resultado
    no header Authorization. Use isto ANTES de confiar em qualquer payload de
    webhook - nunca processe um push sem validar a assinatura primeiro.
    """
    base_string = f"{url}|{raw_body.decode('utf-8')}"
    expected = _sign(partner_key, base_string)
    return hmac.compare_digest(expected, received_sign)


@dataclass
class ShopeeTokenSet:
    access_token: str
    refresh_token: str
    expires_at: float
    shop_id: int

    def is_expired(self, skew_seconds: int = 60) -> bool:
        return time.time() >= (self.expires_at - skew_seconds)

    def to_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "shop_id": self.shop_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ShopeeTokenSet":
        return cls(**data)


class ShopeeAuth:
    def __init__(self, partner_id: int, partner_key: str, redirect_uri: str, env: str = "test") -> None:
        if env not in HOSTS:
            raise ShopeeAuthError('env deve ser "test" (sandbox) ou "live" (producao).')
        self._partner_id = partner_id
        self._partner_key = partner_key
        self._redirect_uri = redirect_uri
        self._host = HOSTS[env]

    def build_authorization_url(self, state: str) -> str:
        timestamp = int(time.time())
        base_string = f"{self._partner_id}{AUTH_PATH}{timestamp}"
        sign = _sign(self._partner_key, base_string)
        params = {
            "partner_id": self._partner_id,
            "timestamp": timestamp,
            "sign": sign,
            "redirect": self._redirect_uri,
            "state": state,
        }
        return f"{self._host}{AUTH_PATH}?{urlencode(params)}"

    def exchange_code(self, code: str, shop_id: int) -> ShopeeTokenSet:
        timestamp = int(time.time())
        base_string = f"{self._partner_id}{TOKEN_GET_PATH}{timestamp}"
        sign = _sign(self._partner_key, base_string)
        body = {
            "code": code,
            "shop_id": shop_id,
            "partner_id": self._partner_id,
        }
        params = {"partner_id": self._partner_id, "timestamp": timestamp, "sign": sign}
        return self._post_token(TOKEN_GET_PATH, params, body, shop_id)

    def refresh(self, refresh_token: str, shop_id: int) -> ShopeeTokenSet:
        timestamp = int(time.time())
        base_string = f"{self._partner_id}{TOKEN_REFRESH_PATH}{timestamp}"
        sign = _sign(self._partner_key, base_string)
        body = {
            "refresh_token": refresh_token,
            "shop_id": shop_id,
            "partner_id": self._partner_id,
        }
        params = {"partner_id": self._partner_id, "timestamp": timestamp, "sign": sign}
        return self._post_token(TOKEN_REFRESH_PATH, params, body, shop_id)

    def _post_token(self, path: str, params: dict, body: dict, shop_id: int) -> ShopeeTokenSet:
        try:
            response = requests.post(
                f"{self._host}{path}",
                params=params,
                json=body,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise ShopeeAuthError(f"Falha de rede ao chamar {path}: {exc}") from exc

        if response.status_code != 200:
            raise ShopeeAuthError(f"Erro ao obter token ({response.status_code}): {response.text}")

        data = response.json()
        if data.get("error"):
            raise ShopeeAuthError(f"Shopee retornou erro: {data.get('error')} - {data.get('message')}")

        return ShopeeTokenSet(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_at=time.time() + float(data.get("expire_in", 4 * 3600)),
            shop_id=shop_id,
        )

    def sign_request(self, path: str, access_token: str | None = None, shop_id: int | None = None) -> dict:
        """Gera {partner_id, timestamp, sign[, access_token, shop_id]} para uma chamada autenticada."""
        timestamp = int(time.time())
        base_string = f"{self._partner_id}{path}{timestamp}"
        if access_token:
            base_string += f"{access_token}{shop_id}"
        sign = _sign(self._partner_key, base_string)
        params = {"partner_id": self._partner_id, "timestamp": timestamp, "sign": sign}
        if access_token:
            params["access_token"] = access_token
            params["shop_id"] = shop_id
        return params

    @property
    def host(self) -> str:
        return self._host
