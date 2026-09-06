import pytest

import config


ML_VARS = ["ML_CLIENT_ID", "ML_CLIENT_SECRET", "ML_REDIRECT_URI", "ML_SITE_ID"]
SHOPEE_VARS = [
    "SHOPEE_PARTNER_ID",
    "SHOPEE_PARTNER_KEY",
    "SHOPEE_REDIRECT_URI",
    "SHOPEE_SHOP_ID",
    "SHOPEE_ENV",
]
SHOPEE_AFFILIATE_VARS = ["SHOPEE_AFFILIATE_APP_ID", "SHOPEE_AFFILIATE_APP_SECRET"]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Garante que nenhuma variavel relevante vaze entre os testes."""
    for name in ML_VARS + SHOPEE_VARS + SHOPEE_AFFILIATE_VARS + ["TOKEN_ENCRYPTION_KEY"]:
        monkeypatch.delenv(name, raising=False)


class TestRequire:
    def test_raises_when_missing(self):
        with pytest.raises(config.ConfigError):
            config._require("SOME_MISSING_VAR")

    def test_raises_when_empty_or_blank(self, monkeypatch):
        monkeypatch.setenv("SOME_VAR", "   ")
        with pytest.raises(config.ConfigError):
            config._require("SOME_VAR")

    def test_returns_stripped_value(self, monkeypatch):
        monkeypatch.setenv("SOME_VAR", "  value  ")
        assert config._require("SOME_VAR") == "value"


class TestOptional:
    def test_returns_default_when_missing(self):
        assert config._optional("SOME_VAR", "default") == "default"
        assert config._optional("SOME_VAR") == ""

    def test_returns_stripped_value_when_present(self, monkeypatch):
        monkeypatch.setenv("SOME_VAR", "  value  ")
        assert config._optional("SOME_VAR", "default") == "value"


class TestMercadoLivreConfig:
    def test_from_env_success_with_default_site_id(self, monkeypatch):
        monkeypatch.setenv("ML_CLIENT_ID", "client-id")
        monkeypatch.setenv("ML_CLIENT_SECRET", "client-secret")
        monkeypatch.setenv("ML_REDIRECT_URI", "https://example.com/callback")

        cfg = config.MercadoLivreConfig.from_env()

        assert cfg.client_id == "client-id"
        assert cfg.client_secret == "client-secret"
        assert cfg.redirect_uri == "https://example.com/callback"
        assert cfg.site_id == "MLB"

    def test_from_env_respects_custom_site_id(self, monkeypatch):
        monkeypatch.setenv("ML_CLIENT_ID", "client-id")
        monkeypatch.setenv("ML_CLIENT_SECRET", "client-secret")
        monkeypatch.setenv("ML_REDIRECT_URI", "https://example.com/callback")
        monkeypatch.setenv("ML_SITE_ID", "MLA")

        cfg = config.MercadoLivreConfig.from_env()

        assert cfg.site_id == "MLA"

    @pytest.mark.parametrize("missing", ["ML_CLIENT_ID", "ML_CLIENT_SECRET", "ML_REDIRECT_URI"])
    def test_from_env_raises_when_required_var_missing(self, monkeypatch, missing):
        values = {
            "ML_CLIENT_ID": "client-id",
            "ML_CLIENT_SECRET": "client-secret",
            "ML_REDIRECT_URI": "https://example.com/callback",
        }
        values.pop(missing)
        for name, value in values.items():
            monkeypatch.setenv(name, value)

        with pytest.raises(config.ConfigError):
            config.MercadoLivreConfig.from_env()

    def test_config_is_frozen(self, monkeypatch):
        monkeypatch.setenv("ML_CLIENT_ID", "client-id")
        monkeypatch.setenv("ML_CLIENT_SECRET", "client-secret")
        monkeypatch.setenv("ML_REDIRECT_URI", "https://example.com/callback")
        cfg = config.MercadoLivreConfig.from_env()

        with pytest.raises(Exception):
            cfg.client_id = "other"


class TestShopeeConfig:
    def _set_required(self, monkeypatch):
        monkeypatch.setenv("SHOPEE_PARTNER_ID", "12345")
        monkeypatch.setenv("SHOPEE_PARTNER_KEY", "partner-key")
        monkeypatch.setenv("SHOPEE_REDIRECT_URI", "https://example.com/shopee")

    def test_from_env_success_defaults(self, monkeypatch):
        self._set_required(monkeypatch)

        cfg = config.ShopeeConfig.from_env()

        assert cfg.partner_id == 12345
        assert cfg.partner_key == "partner-key"
        assert cfg.redirect_uri == "https://example.com/shopee"
        assert cfg.shop_id is None
        assert cfg.env == "test"

    def test_from_env_with_shop_id_and_live_env(self, monkeypatch):
        self._set_required(monkeypatch)
        monkeypatch.setenv("SHOPEE_SHOP_ID", "999")
        monkeypatch.setenv("SHOPEE_ENV", "LIVE")

        cfg = config.ShopeeConfig.from_env()

        assert cfg.shop_id == 999
        assert cfg.env == "live"

    def test_from_env_invalid_env_raises(self, monkeypatch):
        self._set_required(monkeypatch)
        monkeypatch.setenv("SHOPEE_ENV", "staging")

        with pytest.raises(config.ConfigError):
            config.ShopeeConfig.from_env()

    def test_from_env_raises_when_partner_id_missing(self, monkeypatch):
        monkeypatch.setenv("SHOPEE_PARTNER_KEY", "partner-key")
        monkeypatch.setenv("SHOPEE_REDIRECT_URI", "https://example.com/shopee")

        with pytest.raises(config.ConfigError):
            config.ShopeeConfig.from_env()


class TestShopeeAffiliateConfig:
    def test_from_env_success(self, monkeypatch):
        monkeypatch.setenv("SHOPEE_AFFILIATE_APP_ID", "app-id")
        monkeypatch.setenv("SHOPEE_AFFILIATE_APP_SECRET", "app-secret")

        cfg = config.ShopeeAffiliateConfig.from_env()

        assert cfg.app_id == "app-id"
        assert cfg.app_secret == "app-secret"

    def test_from_env_raises_when_missing(self):
        with pytest.raises(config.ConfigError):
            config.ShopeeAffiliateConfig.from_env()


class TestTokenEncryptionKey:
    def test_returns_bytes(self, monkeypatch):
        monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", "my-fernet-key")

        key = config.token_encryption_key()

        assert key == b"my-fernet-key"
        assert isinstance(key, bytes)

    def test_raises_when_missing(self):
        with pytest.raises(config.ConfigError):
            config.token_encryption_key()
