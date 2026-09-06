"""
Exemplo: listar os itens da SUA propria loja Shopee (requer que voce ja tenha
autorizado o app pelo fluxo de auth_partner e tenha um token salvo).

Este exemplo assume que voce ja tem um ShopeeTokenSet (obtido manualmente via
ShopeeAuth().build_authorization_url() + ShopeeAuth().exchange_code() em um
fluxo equivalente ao examples/ml_oauth_flow.py) salvo em tokens.enc sob a
chave "shopee".

Rode com: python -m examples.shopee_shop_products_example
"""
from __future__ import annotations

import sys

sys.path.append(".")

from config import ShopeeConfig, token_encryption_key  # noqa: E402
from shopee.auth import ShopeeAuth, ShopeeTokenSet  # noqa: E402
from shopee.client import ShopeeClient  # noqa: E402
from storage.token_store import SecureTokenStore  # noqa: E402


def main() -> None:
    cfg = ShopeeConfig.from_env()
    auth = ShopeeAuth(cfg.partner_id, cfg.partner_key, cfg.redirect_uri, env=cfg.env)

    store = SecureTokenStore("tokens.enc", token_encryption_key())
    saved = store.load("shopee")
    if not saved:
        raise SystemExit(
            "Nenhum token Shopee salvo. Gere um via ShopeeAuth().build_authorization_url() "
            "e ShopeeAuth().exchange_code(), e salve o resultado com "
            'store.save("shopee", token_set.to_dict()).'
        )

    token_set = ShopeeTokenSet.from_dict(saved)

    def persist_refresh(new_tokens: ShopeeTokenSet) -> None:
        store.save("shopee", new_tokens.to_dict())

    client = ShopeeClient(auth, token_set, on_token_refresh=persist_refresh)

    items = client.get_item_list(page_size=20)
    print(items)


if __name__ == "__main__":
    main()
