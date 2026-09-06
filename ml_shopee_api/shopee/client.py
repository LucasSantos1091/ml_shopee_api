"""
Cliente HTTP para a Shopee Open Platform API v2 (escopo: a SUA propria loja).

Importante (ja discutido antes de escrever este codigo): esta API so da
acesso aos dados da loja que autorizou o app - nao existe endpoint aqui para
"ver os mais vendidos de outros vendedores". Para esse tipo de dado agregado
de mercado, a via oficial seria a Shopee Affiliate API (veja shopee/affiliate.py),
que exige aprovacao separada no programa de afiliados.
"""
from __future__ import annotations

from typing import Any

import requests

from .auth import ShopeeAuth, ShopeeTokenSet
from .exceptions import ShopeeAPIError

REQUEST_TIMEOUT = 15


class ShopeeClient:
    def __init__(self, auth: ShopeeAuth, token_set: ShopeeTokenSet, on_token_refresh=None) -> None:
        self._auth = auth
        self._tokens = token_set
        self._on_token_refresh = on_token_refresh
        self._session = requests.Session()

    @property
    def tokens(self) -> ShopeeTokenSet:
        return self._tokens

    def _ensure_fresh_token(self) -> None:
        if self._tokens.is_expired():
            new_tokens = self._auth.refresh(self._tokens.refresh_token, self._tokens.shop_id)
            self._tokens = new_tokens
            if self._on_token_refresh:
                self._on_token_refresh(new_tokens)

    def _get(self, path: str, extra_params: dict[str, Any] | None = None) -> Any:
        self._ensure_fresh_token()
        params = self._auth.sign_request(path, self._tokens.access_token, self._tokens.shop_id)
        if extra_params:
            params.update(extra_params)

        try:
            response = self._session.get(
                f"{self._auth.host}{path}", params=params, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            raise ShopeeAPIError(0, str(exc)) from exc

        if response.status_code == 429:
            raise ShopeeAPIError(429, "Rate limit excedido - reduza a frequencia de chamadas.")
        if response.status_code >= 400:
            raise ShopeeAPIError(response.status_code, response.text)

        data = response.json()
        if data.get("error"):
            raise ShopeeAPIError(200, f"{data.get('error')}: {data.get('message')}")
        return data

    # -- endpoints de leitura (escopo: a propria loja) -------------------

    def get_item_list(self, offset: int = 0, page_size: int = 50, item_status: str = "NORMAL") -> dict:
        """GET /api/v2/product/get_item_list"""
        return self._get(
            "/api/v2/product/get_item_list",
            {"offset": offset, "page_size": page_size, "item_status": item_status},
        )

    def get_item_base_info(self, item_id_list: list[int]) -> dict:
        """GET /api/v2/product/get_item_base_info"""
        ids = ",".join(str(i) for i in item_id_list)
        return self._get("/api/v2/product/get_item_base_info", {"item_id_list": ids})

    def get_shop_performance(self) -> dict:
        """GET /api/v2/account_health/shop_performance"""
        return self._get("/api/v2/account_health/shop_performance")
