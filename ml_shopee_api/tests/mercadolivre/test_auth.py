import base64
import hashlib
import re
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from mercadolivre.auth import (
    AUTH_BASE_URL,
    TOKEN_URL,
    MLAuth,
    MLTokenSet,
    PKCEPair,
    generate_pkce_pair,
    generate_state,
)
from mercadolivre.exceptions import MLAuthError

URL_SAFE_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class TestGeneratePkcePair:
    def test_returns_pkce_pair_with_expected_shape(self):
        pkce = generate_pkce_pair()

        assert isinstance(pkce, PKCEPair)
        assert URL_SAFE_RE.match(pkce.verifier)
        assert URL_SAFE_RE.match(pkce.challenge)
        # RFC 7636: code_verifier must be 43-128 chars long.
        assert 43 <= len(pkce.verifier) <= 128

    def test_challenge_is_sha256_s256_of_verifier(self):
        pkce = generate_pkce_pair()

        expected_digest = hashlib.sha256(pkce.verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")

        assert pkce.challenge == expected_challenge

    def test_pairs_are_random(self):
        first = generate_pkce_pair()
        second = generate_pkce_pair()

        assert first.verifier != second.verifier
        assert first.challenge != second.challenge


class TestGenerateState:
    def test_returns_url_safe_random_token(self):
        state = generate_state()

        assert URL_SAFE_RE.match(state)
        assert len(state) > 20

    def test_states_are_unique(self):
        assert generate_state() != generate_state()


class TestMLTokenSet:
    def test_is_expired_true_when_past_expiry(self):
        tokens = MLTokenSet(access_token="a", refresh_token="r", expires_at=time.time() - 10)
        assert tokens.is_expired() is True

    def test_is_expired_false_when_well_in_future(self):
        tokens = MLTokenSet(access_token="a", refresh_token="r", expires_at=time.time() + 3600)
        assert tokens.is_expired() is False

    def test_is_expired_respects_skew(self):
        tokens = MLTokenSet(access_token="a", refresh_token="r", expires_at=time.time() + 30)
        assert tokens.is_expired(skew_seconds=60) is True
        assert tokens.is_expired(skew_seconds=0) is False

    def test_to_dict_and_from_dict_roundtrip(self):
        tokens = MLTokenSet(access_token="a", refresh_token="r", expires_at=123.0, user_id=42)

        restored = MLTokenSet.from_dict(tokens.to_dict())

        assert restored == tokens


class TestBuildAuthorizationUrl:
    def _auth(self, redirect_uri="https://example.com/callback"):
        return MLAuth(client_id="cid", client_secret="secret", redirect_uri=redirect_uri)

    def test_raises_when_redirect_uri_not_https_or_localhost(self):
        auth = self._auth(redirect_uri="http://example.com/callback")
        pkce = generate_pkce_pair()

        with pytest.raises(MLAuthError):
            auth.build_authorization_url(state="state123", pkce=pkce)

    def test_allows_localhost_over_http(self):
        auth = self._auth(redirect_uri="http://localhost:8000/callback")
        pkce = generate_pkce_pair()

        url = auth.build_authorization_url(state="state123", pkce=pkce)

        assert url.startswith(AUTH_BASE_URL)

    def test_builds_expected_query_params(self):
        auth = self._auth()
        pkce = PKCEPair(verifier="verifier123", challenge="challenge123")

        url = auth.build_authorization_url(state="state123", pkce=pkce)

        split = urlsplit(url)
        assert f"{split.scheme}://{split.netloc}{split.path}" == AUTH_BASE_URL
        params = parse_qs(split.query)
        assert params["response_type"] == ["code"]
        assert params["client_id"] == ["cid"]
        assert params["redirect_uri"] == ["https://example.com/callback"]
        assert params["state"] == ["state123"]
        assert params["code_challenge"] == ["challenge123"]
        assert params["code_challenge_method"] == ["S256"]


class TestExchangeCode:
    def test_success_returns_token_set(self, requests_mock):
        requests_mock.post(
            TOKEN_URL,
            json={
                "access_token": "access-123",
                "refresh_token": "refresh-123",
                "expires_in": 21600,
                "user_id": 999,
            },
        )
        auth = MLAuth(client_id="cid", client_secret="secret", redirect_uri="https://example.com/cb")

        before = time.time()
        tokens = auth.exchange_code(code="auth-code", pkce_verifier="verifier123")
        after = time.time()

        assert tokens.access_token == "access-123"
        assert tokens.refresh_token == "refresh-123"
        assert tokens.user_id == 999
        assert before + 21600 <= tokens.expires_at <= after + 21600

        sent = requests_mock.last_request
        assert sent.method == "POST"
        payload = parse_qs(sent.text)
        assert payload["grant_type"] == ["authorization_code"]
        assert payload["client_id"] == ["cid"]
        assert payload["client_secret"] == ["secret"]
        assert payload["code"] == ["auth-code"]
        assert payload["redirect_uri"] == ["https://example.com/cb"]
        assert payload["code_verifier"] == ["verifier123"]

    def test_defaults_expires_in_when_absent(self, requests_mock):
        requests_mock.post(
            TOKEN_URL,
            json={"access_token": "a", "refresh_token": "r"},
        )
        auth = MLAuth(client_id="cid", client_secret="secret", redirect_uri="https://example.com/cb")

        before = time.time()
        tokens = auth.exchange_code(code="auth-code", pkce_verifier="verifier123")

        assert tokens.expires_at >= before + 21600 - 1

    def test_non_200_raises_ml_auth_error(self, requests_mock):
        requests_mock.post(TOKEN_URL, status_code=400, text="invalid_grant")
        auth = MLAuth(client_id="cid", client_secret="secret", redirect_uri="https://example.com/cb")

        with pytest.raises(MLAuthError, match="400"):
            auth.exchange_code(code="bad-code", pkce_verifier="verifier123")

    def test_network_failure_raises_ml_auth_error(self, requests_mock):
        requests_mock.post(TOKEN_URL, exc=requests.ConnectionError("boom"))
        auth = MLAuth(client_id="cid", client_secret="secret", redirect_uri="https://example.com/cb")

        with pytest.raises(MLAuthError):
            auth.exchange_code(code="auth-code", pkce_verifier="verifier123")


class TestRefresh:
    def test_success_sends_refresh_grant(self, requests_mock):
        requests_mock.post(
            TOKEN_URL,
            json={"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 100},
        )
        auth = MLAuth(client_id="cid", client_secret="secret", redirect_uri="https://example.com/cb")

        tokens = auth.refresh(refresh_token="old-refresh")

        assert tokens.access_token == "new-access"
        assert tokens.refresh_token == "new-refresh"

        payload = parse_qs(requests_mock.last_request.text)
        assert payload["grant_type"] == ["refresh_token"]
        assert payload["refresh_token"] == ["old-refresh"]

    def test_non_200_raises_ml_auth_error(self, requests_mock):
        requests_mock.post(TOKEN_URL, status_code=401, text="invalid_token")
        auth = MLAuth(client_id="cid", client_secret="secret", redirect_uri="https://example.com/cb")

        with pytest.raises(MLAuthError, match="401"):
            auth.refresh(refresh_token="old-refresh")
