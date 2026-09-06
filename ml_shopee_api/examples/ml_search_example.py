"""
Exemplo: usar o token salvo por examples/ml_oauth_flow.py para buscar itens.

Rode com: python -m examples.ml_search_example (a partir da raiz do projeto)
"""
from __future__ import annotations

import sys

sys.path.append(".")

from config import MercadoLivreConfig, token_encryption_key  # noqa: E402
from mercadolivre.auth import MLAuth, MLTokenSet  # noqa: E402
from mercadolivre.client import MLClient  # noqa: E402
from storage.token_store import SecureTokenStore  # noqa: E402


def main() -> None:
    cfg = MercadoLivreConfig.from_env()
    auth = MLAuth(cfg.client_id, cfg.client_secret, cfg.redirect_uri)

    store = SecureTokenStore("tokens.enc", token_encryption_key())
    saved = store.load("mercadolivre")
    if not saved:
        raise SystemExit("Nenhum token salvo. Rode primeiro examples/ml_oauth_flow.py.")

    token_set = MLTokenSet.from_dict(saved)

    def persist_refresh(new_tokens: MLTokenSet) -> None:
        # O refresh_token do Mercado Livre e de uso unico - salvar
        # IMEDIATAMENTE apos qualquer refresh evita ficar com um token invalido.
        store.save("mercadolivre", new_tokens.to_dict())

    client = MLClient(auth, token_set, on_token_refresh=persist_refresh)

    result = client.search_items(query="suporte celular moto", site_id=cfg.site_id, limit=10)
    for item in result.get("results", []):
        print(f"- {item['title']} | R$ {item['price']} | vendidos (aprox.): {item.get('sold_quantity', 'n/d')}")


if __name__ == "__main__":
    main()
