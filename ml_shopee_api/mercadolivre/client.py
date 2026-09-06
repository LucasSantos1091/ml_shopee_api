"""
Cliente HTTP para a API do Mercado Livre, com refresh automatico de token.

Lembrete importante (discutido antes de gerar este codigo): o Mercado Livre
tem restringido cada vez mais o acesso NAO autenticado aos endpoints publicos
de busca (varios relatos de erro 403 em /sites/{site}/search sem token). Este
cliente sempre autentica as chamadas. Alem disso, o campo `sold_quantity`
devolvido pela API e uma aproximacao, nao uma contagem exata - nao trate como
numero absoluto de vendas.
"""
from __future__ import annotations

import time
from typing import Any

import requests

from .auth import MLAuth, MLTokenSet
from .exceptions import MLAPIError, MLAuthError

API_BASE_URL = "https://api.mercadolibre.com"
REQUEST_TIMEOUT = 15


class MLClient:
    def __init__(self, auth: MLAuth, token_set: MLTokenSet, on_token_refresh=None) -> None:
        """
        auth: instancia de MLAuth (contem client_id/secret/redirect_uri)
        token_set: par de tokens atual (obtido via MLAuth.exchange_code em algum
                   momento anterior e persistido por voce, ex. com SecureTokenStore)
        on_token_refresh: callback opcional `fn(new_token_set: MLTokenSet)`
                   chamado toda vez que o token e renovado, para voce persistir
                   o novo refresh_token imediatamente (ele e de uso unico).
        """
        self._auth = auth
        self._tokens = token_set
        self._on_token_refresh = on_token_refresh
        self._session = requests.Session()

    @property
    def tokens(self) -> MLTokenSet:
        return self._tokens

    def _ensure_fresh_token(self) -> None:
        if self._tokens.is_expired():
            new_tokens = self._auth.refresh(self._tokens.refresh_token)
            self._tokens = new_tokens
            if self._on_token_refresh:
                self._on_token_refresh(new_tokens)

    def _request(self, method: str, path: str, **kwargs) -> Any:
        self._ensure_fresh_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._tokens.access_token}"
        headers.setdefault("Accept", "application/json")

        url = f"{API_BASE_URL}{path}"
        try:
            response = self._session.request(
                method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs
            )
        except requests.RequestException as exc:
            raise MLAPIError(0, str(exc)) from exc

        # 401 pode significar token invalidado no meio do caminho (ex: revogado
        # manualmente) - tenta um unico refresh antes de desistir.
        if response.status_code == 401:
            new_tokens = self._auth.refresh(self._tokens.refresh_token)
            self._tokens = new_tokens
            if self._on_token_refresh:
                self._on_token_refresh(new_tokens)
            headers["Authorization"] = f"Bearer {self._tokens.access_token}"
            response = self._session.request(
                method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs
            )

        if response.status_code == 429:
            raise MLAPIError(429, "Rate limit excedido - reduza a frequencia de chamadas.")

        if response.status_code >= 400:
            try:
                payload = response.json()
            except ValueError:
                payload = response.text
            raise MLAPIError(response.status_code, payload)

        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    # -- endpoints de leitura ------------------------------------------

    def search_items(
        self,
        query: str | None = None,
        category: str | None = None,
        site_id: str = "MLB",
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """GET /sites/{site_id}/search"""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if query:
            params["q"] = query
        if category:
            params["category"] = category
        return self._request("GET", f"/sites/{site_id}/search", params=params)

    def get_item(self, item_id: str) -> dict:
        """GET /items/{item_id}"""
        return self._request("GET", f"/items/{item_id}")

    def get_trends(self, site_id: str = "MLB", category_id: str | None = None) -> list:
        """GET /trends/{site_id}[/{category_id}] - top termos de busca por categoria."""
        path = f"/trends/{site_id}"
        if category_id:
            path += f"/{category_id}"
        return self._request("GET", path)

    def get_categories(self, site_id: str = "MLB") -> list:
        """GET /sites/{site_id}/categories"""
        return self._request("GET", f"/sites/{site_id}/categories")
