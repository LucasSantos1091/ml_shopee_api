import time

import pytest
import requests

from shopee.auth import HOSTS, TOKEN_REFRESH_PATH, ShopeeAuth, ShopeeTokenSet
from shopee.client import ShopeeClient
from shopee.exceptions import ShopeeAPIError

PARTNER_ID = 12345
PARTNER_KEY = "partner-secret-key"
HOST = HOSTS["test"]


def make_auth():
    return ShopeeAuth(
        partner_id=PARTNER_ID,
        partner_key=PARTNER_KEY,
        redirect_uri="https://example.com/shopee/cb",
        env="test",
    )


def make_fresh_tokens():
    return ShopeeTokenSet(access_token="access-1", refresh_token="refresh-1", expires_at=time.time() + 3600, shop_id=555)


def make_expired_tokens():
    return ShopeeTokenSet(access_token="access-old", refresh_token="refresh-old", expires_at=time.time() - 10, shop_id=555)


class TestTokenRefresh:
    def test_proactive_refresh_when_expired(self, requests_mock):
        requests_mock.post(
            f"{HOST}{TOKEN_REFRESH_PATH}",
            json={"access_token": "access-new", "refresh_token": "refresh-new", "expire_in": 14400},
        )
        requests_mock.get(
            f"{HOST}/api/v2/account_health/shop_performance",
            json={"performance": "ok"},
        )
        refreshed = []
        client = ShopeeClient(make_auth(), make_expired_tokens(), on_token_refresh=refreshed.append)

        result = client.get_shop_performance()

        assert result == {"performance": "ok"}
        assert client.tokens.access_token == "access-new"
        assert len(refreshed) == 1

        get_request = requests_mock.request_history[-1]
        assert get_request.qs["access_token"] == ["access-new"]

    def test_no_refresh_when_fresh(self, requests_mock):
        requests_mock.get(
            f"{HOST}/api/v2/account_health/shop_performance",
            json={"performance": "ok"},
        )
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        client.get_shop_performance()

        assert requests_mock.call_count == 1


class TestErrorHandling:
    def test_429_raises_shopee_api_error(self, requests_mock):
        requests_mock.get(f"{HOST}/api/v2/account_health/shop_performance", status_code=429)
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        with pytest.raises(ShopeeAPIError) as excinfo:
            client.get_shop_performance()
        assert excinfo.value.status_code == 429

    def test_http_error_status_raises_shopee_api_error(self, requests_mock):
        requests_mock.get(f"{HOST}/api/v2/account_health/shop_performance", status_code=500, text="boom")
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        with pytest.raises(ShopeeAPIError) as excinfo:
            client.get_shop_performance()
        assert excinfo.value.status_code == 500

    def test_business_error_in_200_response_raises(self, requests_mock):
        requests_mock.get(
            f"{HOST}/api/v2/account_health/shop_performance",
            json={"error": "invalid_access_token", "message": "token expired"},
        )
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        with pytest.raises(ShopeeAPIError, match="invalid_access_token"):
            client.get_shop_performance()

    def test_network_failure_raises_shopee_api_error(self, requests_mock):
        requests_mock.get(
            f"{HOST}/api/v2/account_health/shop_performance", exc=requests.ConnectionError("boom")
        )
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        with pytest.raises(ShopeeAPIError) as excinfo:
            client.get_shop_performance()
        assert excinfo.value.status_code == 0

    def test_401_is_not_retried(self, requests_mock):
        """Diferente do MLClient, ShopeeClient nao tenta refresh automatico em 401."""
        requests_mock.get(f"{HOST}/api/v2/account_health/shop_performance", status_code=401, text="unauthorized")
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        with pytest.raises(ShopeeAPIError) as excinfo:
            client.get_shop_performance()
        assert excinfo.value.status_code == 401
        assert requests_mock.call_count == 1


class TestReadEndpoints:
    def test_get_item_list_sends_expected_params(self, requests_mock):
        requests_mock.get(f"{HOST}/api/v2/product/get_item_list", json={"item": []})
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        client.get_item_list(offset=10, page_size=20, item_status="BANNED")

        qs = requests_mock.last_request.qs
        assert qs["offset"] == ["10"]
        assert qs["page_size"] == ["20"]
        assert qs["item_status"] == ["banned"]
        assert qs["shop_id"] == ["555"]
        assert qs["access_token"] == ["access-1"]

    def test_get_item_base_info_joins_ids(self, requests_mock):
        requests_mock.get(f"{HOST}/api/v2/product/get_item_base_info", json={"item_list": []})
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        client.get_item_base_info([1, 2, 3])

        qs = requests_mock.last_request.qs
        assert qs["item_id_list"] == ["1,2,3"]

    def test_get_shop_performance(self, requests_mock):
        requests_mock.get(
            f"{HOST}/api/v2/account_health/shop_performance", json={"performance": {"rating": 5}}
        )
        client = ShopeeClient(make_auth(), make_fresh_tokens())

        assert client.get_shop_performance() == {"performance": {"rating": 5}}
