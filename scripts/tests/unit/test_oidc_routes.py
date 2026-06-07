#!/usr/bin/env python3
"""
Unit tests: OIDC routes (GET /initiate, GET /callback, POST /complete).

Uses Flask test_client with a fake OidcService injected in app.config.
No real OIDC provider, no HTTP calls, no JWT.

Covers:
  /initiate:
    1.  OIDC disabled → 404
    2.  Success → 302 to provider URL

  /callback:
    3.  Success → 302 to /next/oidc/callback, Set-Cookie l2n_oidc_exchange
    4.  Cookie flags: HttpOnly, SameSite=Lax, Path=/api/v2/auth/oidc/complete
    5.  Secure flag absent in DEBUG mode, present in production
    6.  exchange_code not present in Location header
    7.  Provider error param → 302 to /next/login?error=oidc_failed
    8.  Missing state or code → 302 to /next/login?error=oidc_failed
    9.  OidcError from service → 302 to /next/login?error=oidc_failed

  /complete:
    10. No cookie → 400
    11. Success → 200 JSON {token, user}, cookie cleared
    12. OidcExchangeError → 400, cookie cleared
    13. OidcUserError → 401 generic message (not str(exc)), cookie cleared

Run from project root:
    python3 scripts/tests/unit/test_oidc_routes.py
"""

import os
import sys
import uuid
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask

from backend.routes_v2.auth_oidc import auth_oidc_v2_bp
from backend.services_v2.oidc_service import (
    OidcDisabledError,
    OidcExchangeError,
    OidcStateError,
    OidcUserError,
)
from backend.models.user import User
from backend.utils.time import utc_now_iso


# ── Constants ─────────────────────────────────────────────────────────────────

_PROVIDER_URL = "https://idp.example.com/auth?response_type=code&state=abc"
_EXCHANGE_CODE = "ex_test-exchange-abc"
_RAW_TOKEN = "l2n_test-raw-api-token-xyz"
_COOKIE = "l2n_oidc_exchange"
_COMPLETE_PATH = "/api/v2/auth/oidc/complete"
_NEXT_CALLBACK = "/next/oidc/callback"
_ERR_REDIRECT = "/next/login?error=oidc_failed"


# ── Fakes ─────────────────────────────────────────────────────────────────────

class FakeSettings:
    DEBUG = True
    OIDC_EXCHANGE_CODE_TTL_SECONDS = 60


class FakeOidcService:
    initiate_raises: Exception | None = None
    handle_callback_raises: Exception | None = None
    complete_login_raises: Exception | None = None

    def __init__(self, complete_result=None):
        self._complete_result = complete_result

    def initiate(self):
        if self.initiate_raises:
            raise self.initiate_raises
        return _PROVIDER_URL, "state-abc"

    def handle_callback(self, state, code):
        if self.handle_callback_raises:
            raise self.handle_callback_raises
        return _EXCHANGE_CODE

    def complete_login(self, exchange_code):
        if self.complete_login_raises:
            raise self.complete_login_raises
        return self._complete_result


def _test_user() -> User:
    ts = utc_now_iso()
    return User(
        id=str(uuid.uuid4()),
        email="alice@example.com",
        display_name="Alice",
        role="user",
        is_active=True,
        created_at=ts,
        updated_at=ts,
    )


def _make_app(svc: FakeOidcService, *, debug: bool = True) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    settings = FakeSettings()
    settings.DEBUG = debug
    app.config["SETTINGS"] = settings
    app.config["OIDC_SERVICE_V2"] = svc
    app.config["APP_SETTINGS_SERVICE_V2"] = None
    app.config["RATE_LIMIT_SERVICE_V2"] = None  # disabled — rate_limit_response returns None
    app.register_blueprint(auth_oidc_v2_bp)
    return app


# ── Cookie helpers ────────────────────────────────────────────────────────────

def _get_cookie(resp, name: str) -> str | None:
    """Return the first Set-Cookie header line for the given cookie name."""
    for v in resp.headers.getlist("Set-Cookie"):
        if v.startswith(name + "="):
            return v
    return None


def _cookie_cleared(resp, name: str) -> bool:
    """True if a Set-Cookie header clears the cookie (Max-Age=0)."""
    for v in resp.headers.getlist("Set-Cookie"):
        if v.startswith(name + "=") and "Max-Age=0" in v:
            return True
    return False


# ── Tests: GET /initiate ──────────────────────────────────────────────────────

class TestOidcInitiate(unittest.TestCase):

    # 1. OIDC disabled → 404
    def test_oidc_disabled_returns_404(self):
        svc = FakeOidcService()
        svc.initiate_raises = OidcDisabledError("not enabled")
        resp = _make_app(svc).test_client().get("/api/v2/auth/oidc/initiate")
        self.assertEqual(resp.status_code, 404)

    # 2. Success → 302 to provider URL
    def test_success_redirects_to_provider(self):
        resp = _make_app(FakeOidcService()).test_client().get(
            "/api/v2/auth/oidc/initiate", follow_redirects=False
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["Location"], _PROVIDER_URL)


# ── Tests: GET /callback ──────────────────────────────────────────────────────

class TestOidcCallback(unittest.TestCase):

    def _get(self, svc, query: str = "state=abc&code=xyz", **app_kw):
        return _make_app(svc, **app_kw).test_client().get(
            f"/api/v2/auth/oidc/callback?{query}", follow_redirects=False
        )

    # 3. Success → 302 to /next/oidc/callback
    def test_success_redirects_to_next_callback(self):
        resp = self._get(FakeOidcService())
        self.assertEqual(resp.status_code, 302)
        self.assertIn(_NEXT_CALLBACK, resp.headers["Location"])

    # 4. Cookie flags
    def test_success_cookie_flags(self):
        resp = self._get(FakeOidcService())
        cookie = _get_cookie(resp, _COOKIE)
        self.assertIsNotNone(cookie, f"Set-Cookie {_COOKIE} must be present")
        self.assertIn(_EXCHANGE_CODE, cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn(f"Path={_COMPLETE_PATH}", cookie)

    # 5. Secure absent in debug, present in production
    def test_cookie_not_secure_in_debug(self):
        resp = self._get(FakeOidcService(), debug=True)
        cookie = _get_cookie(resp, _COOKIE)
        self.assertIsNotNone(cookie)
        self.assertNotIn("Secure", cookie)

    def test_cookie_secure_in_production(self):
        resp = self._get(FakeOidcService(), debug=False)
        cookie = _get_cookie(resp, _COOKIE)
        self.assertIsNotNone(cookie)
        self.assertIn("Secure", cookie)

    # 6. exchange_code not in Location
    def test_exchange_code_not_in_location(self):
        resp = self._get(FakeOidcService())
        self.assertNotIn(_EXCHANGE_CODE, resp.headers.get("Location", ""))

    # 7. Provider error param → error redirect
    def test_provider_error_redirects_to_login(self):
        resp = self._get(FakeOidcService(), query="error=access_denied")
        self.assertEqual(resp.status_code, 302)
        self.assertIn(_ERR_REDIRECT, resp.headers["Location"])

    # 8. Missing state or code → error redirect
    def test_missing_code_redirects_to_login(self):
        resp = self._get(FakeOidcService(), query="state=abc")
        self.assertEqual(resp.status_code, 302)
        self.assertIn(_ERR_REDIRECT, resp.headers["Location"])

    def test_missing_state_redirects_to_login(self):
        resp = self._get(FakeOidcService(), query="code=xyz")
        self.assertEqual(resp.status_code, 302)
        self.assertIn(_ERR_REDIRECT, resp.headers["Location"])

    # 9. OidcError from service → error redirect
    def test_oidc_error_redirects_to_login(self):
        svc = FakeOidcService()
        svc.handle_callback_raises = OidcStateError("bad state")
        resp = self._get(svc)
        self.assertEqual(resp.status_code, 302)
        self.assertIn(_ERR_REDIRECT, resp.headers["Location"])


# ── Tests: POST /complete ─────────────────────────────────────────────────────

class TestOidcComplete(unittest.TestCase):

    def _post(self, svc, exchange_code: str | None = None, **app_kw):
        app = _make_app(svc, **app_kw)
        with app.test_client() as client:
            if exchange_code is not None:
                client.set_cookie(_COOKIE, exchange_code)
            return client.post("/api/v2/auth/oidc/complete")

    # 10. No cookie → 400
    def test_no_cookie_returns_400(self):
        resp = self._post(FakeOidcService(), exchange_code=None)
        self.assertEqual(resp.status_code, 400)

    # 11. Success → 200 JSON, cookie cleared
    def test_success_returns_token_user_and_clears_cookie(self):
        user = _test_user()
        svc = FakeOidcService(complete_result=(_RAW_TOKEN, user))
        resp = self._post(svc, exchange_code="valid-code")

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["token"], _RAW_TOKEN)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["id"], user.id)
        self.assertEqual(data["user"]["email"], user.email)
        self.assertNotIn("password_hash", data["user"])
        self.assertTrue(_cookie_cleared(resp, _COOKIE), "Cookie must be cleared on success")

    # 12. OidcExchangeError → 400, cookie cleared
    def test_exchange_error_returns_400_and_clears_cookie(self):
        svc = FakeOidcService()
        svc.complete_login_raises = OidcExchangeError("bad code")
        resp = self._post(svc, exchange_code="stale-code")

        self.assertEqual(resp.status_code, 400)
        self.assertTrue(_cookie_cleared(resp, _COOKIE), "Cookie must be cleared on exchange error")

    # 13. OidcUserError → generic 401, no str(exc) leak, cookie cleared
    def test_user_error_returns_generic_401_and_clears_cookie(self):
        svc = FakeOidcService()
        svc.complete_login_raises = OidcUserError("User account is disabled")
        resp = self._post(svc, exchange_code="valid-code")

        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertEqual(data["error"], "Authentication failed",
                         "Error message must be generic, not str(exc)")
        self.assertNotIn("User account is disabled", str(data))
        self.assertTrue(_cookie_cleared(resp, _COOKIE), "Cookie must be cleared on user error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
