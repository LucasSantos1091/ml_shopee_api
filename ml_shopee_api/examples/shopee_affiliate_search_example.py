"""
Exemplo: buscar ofertas de produto via Shopee Affiliate API, ordenadas por
volume de vendas - o caminho oficial mais proximo de "ver os mais vendidos".
Exige aprovacao no programa de afiliados da Shopee (credenciais separadas do
app Open Platform).

Rode com: python -m examples.shopee_affiliate_search_example
"""
from __future__ import annotations

import sys

sys.path.append(".")

from config import ShopeeAffiliateConfig  # noqa: E402
from shopee.affiliate import ShopeeAffiliateClient  # noqa: E402


def main() -> None:
    cfg = ShopeeAffiliateConfig.from_env()
    client = ShopeeAffiliateClient(cfg.app_id, cfg.app_secret)

    data = client.search_product_offers("suporte celular moto", sort_by_sales=True, limit=10)
    for node in data["productOfferV2"]["nodes"]:
        print(f"- {node['productName']} | vendas: {node['sales']} | R$ {node['price']}")


if __name__ == "__main__":
    main()
