import hashlib
import json

import pytest
import requests

from shopee.affiliate import GRAPHQL_URL, PRODUCT_OFFER_SEARCH_QUERY, ShopeeAffiliateClient
from shopee.exceptions import ShopeeAPIError

APP_ID = "app-id-123"
APP_SECRET = "app-secret-456"


def make_client():
    return ShopeeAffiliateClient(app_id=APP_ID, app_secret=APP_SECRET)


class TestSign:
    def test_sign_matches_documented_algorithm(self):
        client = make_client()
        timestamp = 1_700_000_000
        payload_str = '{"query":"..."}'

        signature = client._sign(timestamp, payload_str)

        base_string = f"{APP_ID}{timestamp}{payload_str}{APP_SECRET}"
        expected = hashlib.sha256(base_string.encode("utf-8")).hexdigest()
        assert signature == expected

    def test_sign_is_deterministic(self):
        client = make_client()
        assert client._sign(1, "a") == client._sign(1, "a")
        assert client._sign(1, "a") != client._sign(1, "b")


class TestExecute:
    def test_sends_expected_headers_and_body(self, requests_mock):
        requests_mock.post(GRAPHQL_URL, json={"data": {"ok": True}})
        client = make_client()

        result = client._execute("query { ping }", {"foo": "bar"})

        assert result == {"ok": True}
        sent = requests_mock.last_request
        assert sent.headers["Content-Type"] == "application/json"
        auth_header = sent.headers["Authorization"]
        assert auth_header.startswith(f"SHA256 Credential={APP_ID}, Signature=")
        assert ", Timestamp=" in auth_header

        body = json.loads(sent.text)
        assert body == {"query": "query { ping }", "variables": {"foo": "bar"}}

    def test_graphql_errors_raise_shopee_api_error(self, requests_mock):
        requests_mock.post(GRAPHQL_URL, json={"errors": [{"message": "bad query"}]})
        client = make_client()

        with pytest.raises(ShopeeAPIError) as excinfo:
            client._execute("query { ping }", {})
        assert excinfo.value.status_code == 200
        assert excinfo.value.payload == [{"message": "bad query"}]

    def test_http_error_status_raises_shopee_api_error(self, requests_mock):
        requests_mock.post(GRAPHQL_URL, status_code=403, text="forbidden")
        client = make_client()

        with pytest.raises(ShopeeAPIError) as excinfo:
            client._execute("query { ping }", {})
        assert excinfo.value.status_code == 403

    def test_network_failure_raises_shopee_api_error(self, requests_mock):
        requests_mock.post(GRAPHQL_URL, exc=requests.ConnectionError("boom"))
        client = make_client()

        with pytest.raises(ShopeeAPIError) as excinfo:
            client._execute("query { ping }", {})
        assert excinfo.value.status_code == 0


class TestSearchProductOffers:
    def test_sort_by_sales_true_uses_sort_type_2(self, requests_mock):
        requests_mock.post(GRAPHQL_URL, json={"data": {"productOfferV2": {"nodes": []}}})
        client = make_client()

        client.search_product_offers(keyword="mouse", sort_by_sales=True, page=2, limit=10)

        body = json.loads(requests_mock.last_request.text)
        assert body["query"] == PRODUCT_OFFER_SEARCH_QUERY
        assert body["variables"] == {"keyword": "mouse", "sortType": 2, "page": 2, "limit": 10}

    def test_sort_by_sales_false_uses_sort_type_1(self, requests_mock):
        requests_mock.post(GRAPHQL_URL, json={"data": {"productOfferV2": {"nodes": []}}})
        client = make_client()

        client.search_product_offers(keyword="mouse", sort_by_sales=False)

        body = json.loads(requests_mock.last_request.text)
        assert body["variables"]["sortType"] == 1
        assert body["variables"]["page"] == 1
        assert body["variables"]["limit"] == 20

    def test_returns_data_payload(self, requests_mock):
        expected = {"productOfferV2": {"nodes": [{"itemId": 1}]}}
        requests_mock.post(GRAPHQL_URL, json={"data": expected})
        client = make_client()

        result = client.search_product_offers(keyword="mouse")

        assert result == expected
