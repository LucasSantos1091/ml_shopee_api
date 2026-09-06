"""
Carregamento centralizado de configuracao/segredos.

Regra de ouro deste projeto: NENHUM segredo (client_secret, partner_key,
tokens) vive em codigo-fonte. Tudo vem de variaveis de ambiente (.env em
desenvolvimento local; variaveis de ambiente reais / secrets manager em
producao).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Carrega o .env (se existir) para os.environ. Em producao, prefira injetar
# as variaveis diretamente no ambiente (Docker secrets, AWS Secrets Manager,
# GCP Secret Manager, HashiCorp Vault, etc.) em vez de um arquivo .env.
load_dotenv()


class ConfigError(RuntimeError):
    """Levantado quando uma variavel de ambiente obrigatoria esta ausente."""


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"Variavel de ambiente obrigatoria ausente: {name}. "
            f"Confira seu arquivo .env (veja .env.example)."
        )
    return value


def _optional(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass(frozen=True)
class MercadoLivreConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    site_id: str = "MLB"

    @classmethod
    def from_env(cls) -> "MercadoLivreConfig":
        return cls(
            client_id=_require("ML_CLIENT_ID"),
            client_secret=_require("ML_CLIENT_SECRET"),
            redirect_uri=_require("ML_REDIRECT_URI"),
            site_id=_optional("ML_SITE_ID", "MLB"),
        )


@dataclass(frozen=True)
class ShopeeConfig:
    partner_id: int
    partner_key: str
    redirect_uri: str
    shop_id: int | None
    env: str = "test"  # "test" (sandbox) ou "live" (producao)

    @classmethod
    def from_env(cls) -> "ShopeeConfig":
        shop_id_raw = _optional("SHOPEE_SHOP_ID")
        env = _optional("SHOPEE_ENV", "test").lower()
        if env not in ("test", "live"):
            raise ConfigError('SHOPEE_ENV deve ser "test" ou "live".')
        return cls(
            partner_id=int(_require("SHOPEE_PARTNER_ID")),
            partner_key=_require("SHOPEE_PARTNER_KEY"),
            redirect_uri=_require("SHOPEE_REDIRECT_URI"),
            shop_id=int(shop_id_raw) if shop_id_raw else None,
            env=env,
        )


@dataclass(frozen=True)
class ShopeeAffiliateConfig:
    app_id: str
    app_secret: str

    @classmethod
    def from_env(cls) -> "ShopeeAffiliateConfig":
        return cls(
            app_id=_require("SHOPEE_AFFILIATE_APP_ID"),
            app_secret=_require("SHOPEE_AFFILIATE_APP_SECRET"),
        )


def token_encryption_key() -> bytes:
    """
    Chave Fernet usada para criptografar tokens em repouso (storage/token_store.py).

    Gere uma com:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    """
    key = _require("TOKEN_ENCRYPTION_KEY")
    return key.encode("utf-8")
