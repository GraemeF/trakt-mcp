import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from trakt_mcp import auth, runtime


@pytest.fixture(autouse=True)
def reset(monkeypatch, tmp_path):
    monkeypatch.setenv("TRAKT_CLIENT_ID", "cid")
    monkeypatch.delenv("TRAKT_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(runtime, "_TOKEN_PATH", tmp_path / "token.json")
    runtime._http = None
    runtime._token = None
    auth._verifier = None
    yield
    runtime._http = None
    runtime._token = None
    auth._verifier = None


def install(handler):
    runtime._http = httpx.Client(
        base_url=runtime.BASE_URL, transport=httpx.MockTransport(handler)
    )


def authorize_query() -> dict:
    url = json.loads(auth.start_authentication())["authorize_url"]
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == (
        "https://auth.trakt.tv/oauth/authorize"
    )
    return {k: v[0] for k, v in parse_qs(parts.query).items()}


def challenge_of(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def token_response(**overrides):
    return httpx.Response(
        200,
        json={
            "access_token": "tok",
            "refresh_token": "r",
            "expires_in": 604800,
            "created_at": int(time.time()),
            **overrides,
        },
    )


def test_sign_in_starts_with_an_s256_challenge_of_a_fresh_verifier():
    query = authorize_query()
    assert query["response_type"] == "code"
    assert query["client_id"] == "cid"
    assert query["redirect_uri"] == "urn:ietf:wg:oauth:2.0:oob"
    assert query["code_challenge_method"] == "S256"
    assert query["code_challenge"] == challenge_of(auth._verifier)
    assert "client_secret" not in query


def test_the_verifier_is_long_random_and_url_safe():
    authorize_query()
    first = auth._verifier
    authorize_query()
    assert auth._verifier != first
    assert 43 <= len(first) <= 128
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert set(first) <= allowed


def test_finishing_exchanges_the_code_with_the_verifier_and_no_secret():
    authorize_query()
    verifier = auth._verifier
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return token_response()

    install(handler)
    result = json.loads(auth.finish_authentication("  the-code \n"))

    assert result["authenticated"] is True
    assert seen["url"] == "https://auth.trakt.tv/oauth/token"
    assert seen["body"] == {
        "code": "the-code",
        "code_verifier": verifier,
        "client_id": "cid",
        "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        "grant_type": "authorization_code",
    }
    assert runtime.load_token()["access_token"] == "tok"


def test_the_verifier_is_discarded_once_used():
    authorize_query()
    install(lambda request: token_response())
    auth.finish_authentication("the-code")
    assert auth._verifier is None
    result = json.loads(auth.finish_authentication("the-code"))
    assert result["status"] == "error"
    assert "start_authentication" in result["message"]


def test_finishing_without_starting_says_to_start():
    install(lambda request: pytest.fail("nothing should be sent"))
    result = json.loads(auth.finish_authentication("the-code"))
    assert result["status"] == "error"
    assert "start_authentication" in result["message"]


def test_a_refused_code_reports_why_and_allows_another_try():
    authorize_query()
    verifier = auth._verifier
    install(
        lambda request: httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "invalid code"}
        )
    )
    result = json.loads(auth.finish_authentication("typo"))
    assert result["status"] == "error"
    assert "invalid code" in result["message"]
    assert auth._verifier == verifier
    assert runtime.load_token() is None


def test_a_signed_in_token_survives_a_restart():
    authorize_query()
    install(lambda request: token_response())
    auth.finish_authentication("the-code")

    runtime._token = None  # a fresh process has only the file
    status = json.loads(auth.get_authentication_status())
    assert status["authenticated"] is True
    assert status["can_refresh"] is True


def test_refresh_needs_no_secret():
    runtime.store_token(
        {
            "access_token": "old",
            "refresh_token": "r",
            "expires_in": 60,
            "created_at": int(time.time()),
        }
    )
    seen = {}

    def handler(request):
        if request.url.path == "/oauth/token":
            seen["url"] = str(request.url)
            seen["body"] = json.loads(request.content)
            return token_response(access_token="new", refresh_token="r2")
        return httpx.Response(200, json=[])

    install(handler)
    runtime.call("GET", "/sync/history")

    assert seen["url"] == "https://auth.trakt.tv/oauth/token"
    assert seen["body"] == {
        "refresh_token": "r",
        "client_id": "cid",
        "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        "grant_type": "refresh_token",
    }
    assert runtime.load_token()["refresh_token"] == "r2"


def test_signing_out_revokes_without_a_secret():
    runtime.store_token({"access_token": "tok", "expires_in": 60, "created_at": 0})
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200)

    install(handler)
    result = json.loads(auth.clear_authentication())

    assert result["cleared"] is True
    assert seen["url"] == "https://auth.trakt.tv/oauth/revoke"
    assert seen["body"] == {"token": "tok", "client_id": "cid"}
    assert runtime.load_token() is None
