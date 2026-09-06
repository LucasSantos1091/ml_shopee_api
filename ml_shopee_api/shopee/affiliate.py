"""
Cliente para a Shopee Affiliate API (GraphQL) - opcional.

Esta e a API mais proxima do que voce queria originalmente (buscar anuncios
por palavra-chave/categoria e ordenar por volume de vendas). Ela e distinta
da Open Platform API acima: usa App ID + App Secret proprios do programa de
afiliados, e exige aprovacao separada (cadastro no programa de afiliados da
Shopee + solicitacao formal de acesso a API - historicamente com prazo de
ate 2 semanas). Nao confunda as credenciais dela com as do app Open Platform.

Assinatura usada (header Authorization):
  payload_str = corpo da requisicao GraphQL (JSON), como string
  base_string = f"{app_id}{timestamp}{payload_str}{app_secret}"
  signature = SHA256(base_string).hexdigest()
  Authorization: SHA256 Credential={app_id}, Signature={signature}, Timestamp={timestamp}

O app_secret so e usado localmente para gerar o hash - nunca trafega na
requisicao nem deve ser logado.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import requests

from .exceptions import ShopeeAPIError

GRAPHQL_URL = "https://open-api.affiliate.shopee.com.br/graphql"
REQUEST_TIMEOUT = 15

# Exemplo de query: busca ofertas de produto por palavra-chave, ordenadas por
# volume de vendas. Confirme os nomes exatos de campo/enum na doc oficial da
# Affiliate API antes de usar em producao - GraphQL schemas mudam com o tempo.
PRODUCT_OFFER_SEARCH_QUERY = """
query ProductOfferSearch($keyword: String, $sortType: Int, $page: Int, $limit: Int) {
  productOfferV2(keyword: $keyword, sortType: $sortType, page: $page, limit: $limit) {
    nodes {
      itemId
      productName
      price
      sales
      commissionRate
      shopName
      offerLink
    }
    pageInfo {
      page
      limit
      hasNextPage
    }
  }
}
"""


class ShopeeAffiliateClient:
    def __init__(self, app_id: str, app_secret: str) -> None:
        self._app_id = app_id
        self._app_secret = app_secret
        self._session = requests.Session()

    def _sign(self, timestamp: int, payload_str: str) -> str:
        base_string = f"{self._app_id}{timestamp}{payload_str}{self._app_secret}"
        return hashlib.sha256(base_string.encode("utf-8")).hexdigest()

    def _execute(self, query: str, variables: dict[str, Any]) -> dict:
        body = {"query": query, "variables": variables}
        payload_str = json.dumps(body, separators=(",", ":"))
        timestamp = int(time.time())
        signature = self._sign(timestamp, payload_str)

        headers = {
            "Content-Type": "application/json",
            "Authorization": (
                f"SHA256 Credential={self._app_id}, "
                f"Signature={signature}, Timestamp={timestamp}"
            ),
        }

        try:
            response = self._session.post(
                GRAPHQL_URL, data=payload_str, headers=headers, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            raise ShopeeAPIError(0, str(exc)) from exc

        if response.status_code >= 400:
            raise ShopeeAPIError(response.status_code, response.text)

        data = response.json()
        if "errors" in data:
            raise ShopeeAPIError(200, data["errors"])
        return data["data"]

    def search_product_offers(
        self, keyword: str, sort_by_sales: bool = True, page: int = 1, limit: int = 20
    ) -> dict:
        """
        Busca ofertas de produto por palavra-chave (ex: "suporte celular moto"),
        ordenadas por volume de vendas quando sort_by_sales=True.
        """
        variables = {
            "keyword": keyword,
            "sortType": 2 if sort_by_sales else 1,  # confirme os codigos na doc oficial
            "page": page,
            "limit": limit,
        }
        return self._execute(PRODUCT_OFFER_SEARCH_QUERY, variables)
