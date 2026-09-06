"""
Fluxo OAuth2 (Authorization Code + PKCE) do Mercado Livre.

Referencia oficial: https://developers.mercadolivre.com.br/pt_br/autenticacao-e-autorizacao
(cheque a documentacao oficial antes de ir para producao - detalhes de OAuth
mudam com o tempo; os valores abaixo foram confirmados em 08/2026).

Pontos de seguranca implementados aqui:
  - PKCE (code_verifier/code_challenge com S256) mesmo sendo "opcional" na doc,
    porque protege contra interceptacao do "code" em apps publicos/desktop.
  - "state" aleatorio e imprevisivel (secrets.token_urlsafe), validado no
    callback para mitigar CSRF no fluxo OAuth.
  - client_secret so e usado aqui, no backend - nunca deve ir para um
    frontend/app mobile/repositorio publico.
  - O refresh_token do Mercado Livre e de uso UNICO: a cada refresh, a API
    devolve um novo refresh_token e o antigo deixa de funcionar. Este modulo
    sempre persiste o novo par (access_token, refresh_token) imediatamente
    apos qualquer troca, para nunca "perder" o refresh_token valido.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import requests

from .exceptions import MLAuthError

AUTH_BASE_URL = "https://auth.mercadolivre.com.br/authorization"
TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
REQUEST_TIMEOUT = 15  # segundos - nunca faca requests sem timeout


@dataclass
class PKCEPair:
    verifier: str
    challenge: str


def generate_pkce_pair() -> PKCEPair:
    # 32 bytes aleatorios -> ~43 chars base64url, dentro do range exigido (43-128)
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PKCEPair(verifier=verifier, challenge=challenge)


def generate_state() -> str:
    """Token aleatorio para protecao CSRF no fluxo OAuth. Guarde-o em sessao
    (nao em cookie sem assinatura) e compare no callback antes de trocar o code."""
    return secrets.token_urlsafe(32)


@dataclass
class MLTokenSet:
    access_token: str
    refresh_token: str
    expires_at: float  # epoch seconds
    user_id: int | None = None

    def is_expired(self, skew_seconds: int = 60) -> bool:
        return time.time() >= (self.expires_at - skew_seconds)

    def to_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MLTokenSet":
        return cls(**data)


class MLAuth:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    def build_authorization_url(self, state: str, pkce: PKCEPair) -> str:
        if not self._redirect_uri.startswith("https://") and "localhost" not in self._redirect_uri:
            raise MLAuthError(
                "redirect_uri deve usar HTTPS em producao. "
                "'http://localhost' so e aceitavel para desenvolvimento local."
            )
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "state": state,
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
        }
        return f"{AUTH_BASE_URL}?{urlencode(params)}"

    def exchange_code(self, code: str, pkce_verifier: str) -> MLTokenSet:
        payload = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "redirect_uri": self._redirect_uri,
            "code_verifier": pkce_verifier,
        }
        return self._post_token(payload)

    def refresh(self, refresh_token: str) -> MLTokenSet:
        payload = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": refresh_token,
        }
        return self._post_token(payload)

    def _post_token(self, payload: dict) -> MLTokenSet:
        try:
            response = requests.post(
                TOKEN_URL,
                data=payload,
                headers={"Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise MLAuthError(f"Falha de rede ao chamar o endpoint de token: {exc}") from exc

        if response.status_code != 200:
            # Nunca ecoar o client_secret/refresh_token no erro - so o corpo
            # de resposta da API (que nao contem nossos segredos de entrada).
            raise MLAuthError(f"Erro ao obter token ({response.status_code}): {response.text}")

        body = response.json()
        return MLTokenSet(
            access_token=body["access_token"],
            refresh_token=body["refresh_token"],
            expires_at=time.time() + float(body.get("expires_in", 21600)),
            user_id=body.get("user_id"),
        )
