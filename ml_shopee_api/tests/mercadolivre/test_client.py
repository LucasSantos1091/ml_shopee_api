import time

import pytest
import requests

from mercadolivre.auth import MLAuth, MLTokenSet, TOKEN_URL
from mercadolivre.client import API_BASE_URL, MLClient
from mercadolivre.exceptions import MLAPIError


def make_auth():
    return MLAuth(client_id="cid", client_secret="secret", redirect_uri="https://example.com/cb")


def make_fresh_tokens():
    return MLTokenSet(access_token="access-1", refresh_token="refresh-1", expires_at=time.time() + 3600)


def make_expired_tokens():
    return MLTokenSet(access_token="access-old", refresh_token="refresh-old", expires_at=time.time() - 10)


class TestTokenRefresh:
    def test_proactive_refresh_when_expired(self, requests_mock):
        requests_mock.post(
            TOKEN_URL,
            json={"access_token": "access-new", "refresh_token": "refresh-new", "expires_in": 3600},
        )
        requests_mock.get(f"{API_BASE_URL}/items/MLB123", json={"id": "MLB123"})

        refreshed = []
        client = MLClient(make_auth(), make_expired_tokens(), on_token_refresh=refreshed.append)

        client.get_item("MLB123")

        assert client.tokens.access_token == "access-new"
        assert len(refreshed) == 1
        assert refreshed[0].access_token == "access-new"

        item_request = requests_mock.request_history[-1]
        assert item_request.headers["Authorization"] == "Bearer access-new"

    def test_no_refresh_when_token_still_fresh(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/items/MLB123", json={"id": "MLB123"})
        client = MLClient(make_auth(), make_fresh_tokens())

        client.get_item("MLB123")

        assert requests_mock.call_count == 1
        assert requests_mock.last_request.headers["Authorization"] == "Bearer access-1"

    def test_401_triggers_single_retry_after_refresh(self, requests_mock):
        requests_mock.post(
            TOKEN_URL,
            json={"access_token": "access-retry", "refresh_token": "refresh-retry", "expires_in": 3600},
        )
        requests_mock.get(
            f"{API_BASE_URL}/items/MLB123",
            [
                {"status_code": 401, "json": {"message": "invalid token"}},
                {"status_code": 200, "json": {"id": "MLB123"}},
            ],
        )
        refreshed = []
        client = MLClient(make_auth(), make_fresh_tokens(), on_token_refresh=refreshed.append)

        result = client.get_item("MLB123")

        assert result == {"id": "MLB123"}
        assert client.tokens.access_token == "access-retry"
        assert len(refreshed) == 1
        # 2 GET calls (401 then retry) + 1 POST refresh
        get_calls = [r for r in requests_mock.request_history if r.method == "GET"]
        assert len(get_calls) == 2
        assert get_calls[-1].headers["Authorization"] == "Bearer access-retry"


class TestErrorHandling:
    def test_429_raises_ml_api_error(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/items/MLB123", status_code=429)
        client = MLClient(make_auth(), make_fresh_tokens())

        with pytest.raises(MLAPIError) as excinfo:
            client.get_item("MLB123")
        assert excinfo.value.status_code == 429

    def test_generic_error_raises_with_json_payload(self, requests_mock):
        requests_mock.get(
            f"{API_BASE_URL}/items/MLB123",
            status_code=404,
            json={"message": "not found"},
        )
        client = MLClient(make_auth(), make_fresh_tokens())

        with pytest.raises(MLAPIError) as excinfo:
            client.get_item("MLB123")
        assert excinfo.value.status_code == 404
        assert excinfo.value.payload == {"message": "not found"}

    def test_generic_error_with_non_json_body_uses_text(self, requests_mock):
        requests_mock.get(
            f"{API_BASE_URL}/items/MLB123",
            status_code=500,
            text="internal error",
        )
        client = MLClient(make_auth(), make_fresh_tokens())

        with pytest.raises(MLAPIError) as excinfo:
            client.get_item("MLB123")
        assert excinfo.value.status_code == 500
        assert excinfo.value.payload == "internal error"

    def test_network_failure_raises_ml_api_error(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/items/MLB123", exc=requests.ConnectionError("boom"))
        client = MLClient(make_auth(), make_fresh_tokens())

        with pytest.raises(MLAPIError) as excinfo:
            client.get_item("MLB123")
        assert excinfo.value.status_code == 0

    def test_204_returns_none(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/items/MLB123", status_code=204)
        client = MLClient(make_auth(), make_fresh_tokens())

        assert client.get_item("MLB123") is None

    def test_empty_body_returns_none(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/items/MLB123", status_code=200, content=b"")
        client = MLClient(make_auth(), make_fresh_tokens())

        assert client.get_item("MLB123") is None


class TestReadEndpoints:
    def test_search_items_sends_expected_params(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/sites/MLB/search", json={"results": []})
        client = MLClient(make_auth(), make_fresh_tokens())

        client.search_items(query="notebook", category="MLB1000", limit=10, offset=5)

        qs = requests_mock.last_request.qs
        assert qs["q"] == ["notebook"]
        assert qs["category"] == ["mlb1000"]
        assert qs["limit"] == ["10"]
        assert qs["offset"] == ["5"]

    def test_search_items_omits_optional_params(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/sites/MLB/search", json={"results": []})
        client = MLClient(make_auth(), make_fresh_tokens())

        client.search_items()

        qs = requests_mock.last_request.qs
        assert "q" not in qs
        assert "category" not in qs
        assert qs["limit"] == ["50"]
        assert qs["offset"] == ["0"]

    def test_search_items_uses_custom_site_id(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/sites/MLA/search", json={"results": []})
        client = MLClient(make_auth(), make_fresh_tokens())

        client.search_items(site_id="MLA")

        assert requests_mock.last_request.path.lower() == "/sites/mla/search"

    def test_get_item(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/items/MLB123", json={"id": "MLB123"})
        client = MLClient(make_auth(), make_fresh_tokens())

        assert client.get_item("MLB123") == {"id": "MLB123"}

    def test_get_trends_without_category(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/trends/MLB", json=[{"keyword": "phone"}])
        client = MLClient(make_auth(), make_fresh_tokens())

        result = client.get_trends()

        assert result == [{"keyword": "phone"}]
        assert requests_mock.last_request.path.lower() == "/trends/mlb"

    def test_get_trends_with_category(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/trends/MLB/MLB1000", json=[{"keyword": "phone"}])
        client = MLClient(make_auth(), make_fresh_tokens())

        client.get_trends(category_id="MLB1000")

        assert requests_mock.last_request.path.lower() == "/trends/mlb/mlb1000"

    def test_get_categories(self, requests_mock):
        requests_mock.get(f"{API_BASE_URL}/sites/MLB/categories", json=[{"id": "MLB1000"}])
        client = MLClient(make_auth(), make_fresh_tokens())

        assert client.get_categories() == [{"id": "MLB1000"}]
