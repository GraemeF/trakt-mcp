"""PKCE sign-in, kept out of the generated tools.

Trakt's OAuth endpoints are not part of the API contract the tools come from,
and the flow needs state across two calls, so these four are written by hand.

Ref: https://developer.trakt.tv/docs/pkce
"""

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

import httpx

from .runtime import (
    _DESTRUCTIVE,
    _READ,
    _WRITE,
    AUTH_URL,
    REDIRECT_URI,
    _client,
    _detail,
    _err,
    clear_token,
    client_id,
    load_token,
    mcp,
    store_token,
)

# The verifier of the sign-in in progress. Trakt checks the code against it, so
# it lives only in memory and only until its code is exchanged.
_verifier: str | None = None


def _ok(data: dict) -> str:
    return json.dumps({"status": "success", **data}, indent=2)


def _failed(message: str) -> str:
    return json.dumps({"status": "error", "message": message})


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@mcp.tool(annotations=_WRITE)
def start_authentication() -> str:
    """Begin signing in to Trakt.

    Returns a URL. Open it, sign in and approve, then call
    finish_authentication with the code Trakt shows. Only needed for the
    endpoints that act on an account: sync, users/me, checkin, scrobble,
    recommendations and lists you own.
    """
    global _verifier
    try:
        verifier = secrets.token_urlsafe(64)
        query = urlencode(
            {
                "response_type": "code",
                "client_id": client_id(),
                "redirect_uri": REDIRECT_URI,
                "code_challenge": _challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        _verifier = verifier
        return _ok(
            {
                "authorize_url": f"{AUTH_URL}/oauth/authorize?{query}",
                "next_step": (
                    "Open authorize_url, sign in and approve, then call "
                    "finish_authentication with the code Trakt shows."
                ),
            }
        )
    except Exception as e:
        return _err(e)


@mcp.tool(annotations=_WRITE)
def finish_authentication(code: str) -> str:
    """Exchange the code Trakt showed after sign-in for a stored token.

    Args:
        code: The authorization code Trakt displayed once you approved.
    """
    global _verifier
    try:
        if _verifier is None:
            return _failed("No sign-in in progress. Run start_authentication first.")

        response = _client().post(
            f"{AUTH_URL}/oauth/token",
            json={
                "code": code.strip(),
                "code_verifier": _verifier,
                "client_id": client_id(),
                "redirect_uri": REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )
        if response.status_code != 200:
            return _failed(
                f"Trakt refused the code (HTTP {response.status_code}): "
                f"{_detail(response)}. Check the code and try again, or run "
                "start_authentication for a new one."
            )

        store_token(response.json())
        _verifier = None
        return _ok({"authenticated": True})
    except Exception as e:
        return _err(e)


@mcp.tool(annotations=_READ)
def get_authentication_status() -> str:
    """Report whether an account is signed in and when the token expires."""
    try:
        token = load_token()
        if not token:
            return _ok({"authenticated": False})
        expires_at = token.get("expires_at", 0)
        return _ok(
            {
                "authenticated": True,
                "expires_at": expires_at,
                "expires_in_seconds": max(0, int(expires_at - time.time())),
                "can_refresh": bool(token.get("refresh_token")),
            }
        )
    except Exception as e:
        return _err(e)


@mcp.tool(annotations=_DESTRUCTIVE)
def clear_authentication() -> str:
    """Revoke the stored token and forget it."""
    try:
        token = load_token()
        if token:
            try:
                _client().post(
                    f"{AUTH_URL}/oauth/revoke",
                    json={"token": token.get("access_token"), "client_id": client_id()},
                )
            except httpx.HTTPError:
                # A token Trakt has already dropped still has to be forgotten
                # locally, so a failed revoke is not a failed sign-out.
                pass
        return _ok({"cleared": clear_token()})
    except Exception as e:
        return _err(e)
