import hashlib
import hmac
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from shopee.auth import (
    AUTH_PATH,
    HOSTS,
    TOKEN_GET_PATH,
    TOKEN_REFRESH_PATH,
    ShopeeAuth,
    ShopeeTokenSet,
    generate_state,
    verify_push_signature,
)
from shopee.exceptions import ShopeeAuthError

PARTNER_ID = 12345
PARTNER_KEY = "partner-secret-key"


def make_auth(env="test"):
    return ShopeeAuth(
        partner_id=PARTNER_ID,
        partner_key=PARTNER_KEY,
        redirect_uri="https://example.com/shopee/cb",
        env=env,
    )


class TestGenerateState:
    def test_returns_non_empty_unique_tokens(self):
        first = generate_state()
        second = generate_state()

        assert first
        assert first != second


class TestShopeeAuthInit:
    def test_invalid_env_raises(self):
        with pytest.raises(ShopeeAuthError):
            make_auth(env="staging")

    def test_valid_envs_select_expected_host(self):
        assert make_auth(env="test").host == HOSTS["test"]
        assert make_auth(env="live").host == HOSTS["live"]


class TestVerifyPushSignature:
    def test_valid_signature_returns_true(self):
        url = "https://example.com/webhook"
        body = b'{"event": "order_status_update"}'
        base_string = f"{url}|{body.decode('utf-8')}"
        expected = hmac.new(PARTNER_KEY.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha256).hexdigest()

        assert verify_push_signature(body, expected, PARTNER_KEY, url) is True

    def test_tampered_signature_returns_false(self):
        url = "https://example.com/webhook"
        body = b'{"event": "order_status_update"}'

        assert verify_push_signature(body, "0" * 64, PARTNER_KEY, url) is False

    def test_tampered_body_returns_false(self):
        url = "https://example.com/webhook"
        original_body = b'{"event": "order_status_update"}'
        base_string = f"{url}|{original_body.decode('utf-8')}"
        signature = hmac.new(PARTNER_KEY.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha256).hexdigest()

        tampered_body = b'{"event": "order_cancelled"}'
        assert verify_push_signature(tampered_body, signature, PARTNER_KEY, url) is False


class TestShopeeTokenSet:
    def test_is_expired_true_when_past_expiry(self):
        tokens = ShopeeTokenSet(access_token="a", refresh_token="r", expires_at=time.time() - 5, shop_id=1)
        assert tokens.is_expired() is True

    def test_is_expired_false_when_in_future(self):
        tokens = ShopeeTokenSet(access_token="a", refresh_token="r", expires_at=time.time() + 3600, shop_id=1)
        assert tokens.is_expired() is False

    def test_to_dict_and_from_dict_roundtrip(self):
        tokens = ShopeeTokenSet(access_token="a", refresh_token="r", expires_at=100.0, shop_id=7)

        restored = ShopeeTokenSet.from_dict(tokens.to_dict())

        assert restored == tokens


class TestBuildAuthorizationUrl:
    def test_url_uses_test_host_and_expected_params(self):
        auth = make_auth(env="test")

        url = auth.build_authorization_url(state="state-abc")

        split = urlsplit(url)
        assert f"{split.scheme}://{split.netloc}" == HOSTS["test"]
        assert split.path == AUTH_PATH
        params = parse_qs(split.query)
        assert params["partner_id"] == [str(PARTNER_ID)]
        assert params["redirect"] == ["https://example.com/shopee/cb"]
        assert params["state"] == ["state-abc"]
        assert "sign" in params
        assert "timestamp" in params

    def test_signature_matches_expected_algorithm(self):
        auth = make_auth(env="test")

        url = auth.build_authorization_url(state="state-abc")
        params = parse_qs(urlsplit(url).query)
        timestamp = params["timestamp"][0]

        base_string = f"{PARTNER_ID}{AUTH_PATH}{timestamp}"
        expected_sign = hmac.new(
            PARTNER_KEY.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        assert params["sign"] == [expected_sign]

    def test_live_env_uses_live_host(self):
        auth = make_auth(env="live")

        url = auth.build_authorization_url(state="state-abc")

        assert url.startswith(HOSTS["live"])


class TestExchangeCode:
    def test_success_returns_token_set(self, requests_mock):
        requests_mock.post(
            f"{HOSTS['test']}{TOKEN_GET_PATH}",
            json={"access_token": "access-1", "refresh_token": "refresh-1", "expire_in": 14400},
        )
        auth = make_auth(env="test")

        before = time.time()
        tokens = auth.exchange_code(code="auth-code", shop_id=555)

        assert tokens.access_token == "access-1"
        assert tokens.refresh_token == "refresh-1"
        assert tokens.shop_id == 555
        assert tokens.expires_at >= before + 14400 - 1

        sent = requests_mock.last_request
        assert sent.json() == {"code": "auth-code", "shop_id": 555, "partner_id": PARTNER_ID}
        assert sent.qs["partner_id"] == [str(PARTNER_ID)]

    def test_default_expire_in_used_when_absent(self, requests_mock):
        requests_mock.post(
            f"{HOSTS['test']}{TOKEN_GET_PATH}",
            json={"access_token": "access-1", "refresh_token": "refresh-1"},
        )
        auth = make_auth(env="test")

        before = time.time()
        tokens = auth.exchange_code(code="auth-code", shop_id=555)

        assert tokens.expires_at >= before + 4 * 3600 - 1

    def test_business_error_raises_shopee_auth_error(self, requests_mock):
        requests_mock.post(
            f"{HOSTS['test']}{TOKEN_GET_PATH}",
            json={"error": "invalid_code", "message": "code expired"},
        )
        auth = make_auth(env="test")

        with pytest.raises(ShopeeAuthError, match="invalid_code"):
            auth.exchange_code(code="bad-code", shop_id=555)

    def test_non_200_raises_shopee_auth_error(self, requests_mock):
        requests_mock.post(f"{HOSTS['test']}{TOKEN_GET_PATH}", status_code=500, text="boom")
        auth = make_auth(env="test")

        with pytest.raises(ShopeeAuthError, match="500"):
            auth.exchange_code(code="auth-code", shop_id=555)

    def test_network_failure_raises_shopee_auth_error(self, requests_mock):
        requests_mock.post(f"{HOSTS['test']}{TOKEN_GET_PATH}", exc=requests.ConnectionError("boom"))
        auth = make_auth(env="test")

        with pytest.raises(ShopeeAuthError):
            auth.exchange_code(code="auth-code", shop_id=555)


class TestRefresh:
    def test_success_sends_expected_body(self, requests_mock):
        requests_mock.post(
            f"{HOSTS['test']}{TOKEN_REFRESH_PATH}",
            json={"access_token": "access-2", "refresh_token": "refresh-2", "expire_in": 14400},
        )
        auth = make_auth(env="test")

        tokens = auth.refresh(refresh_token="old-refresh", shop_id=555)

        assert tokens.access_token == "access-2"
        assert tokens.refresh_token == "refresh-2"
        assert requests_mock.last_request.json() == {
            "refresh_token": "old-refresh",
            "shop_id": 555,
            "partner_id": PARTNER_ID,
        }


class TestSignRequest:
    def test_public_endpoint_params_have_no_access_token(self):
        auth = make_auth(env="test")

        params = auth.sign_request("/api/v2/some/public/path")

        assert set(params.keys()) == {"partner_id", "timestamp", "sign"}

    def test_shop_endpoint_includes_access_token_and_shop_id(self):
        auth = make_auth(env="test")

        params = auth.sign_request("/api/v2/product/get_item_list", access_token="token-x", shop_id=555)

        assert params["access_token"] == "token-x"
        assert params["shop_id"] == 555
        base_string = f"{PARTNER_ID}/api/v2/product/get_item_list{params['timestamp']}token-x555"
        expected_sign = hmac.new(
            PARTNER_KEY.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        assert params["sign"] == expected_sign
