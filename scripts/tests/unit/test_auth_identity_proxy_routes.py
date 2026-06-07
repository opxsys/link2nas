#!/usr/bin/env python3
"""
Unit tests: POST /api/v2/auth/identity-proxy/login.

No real DB, no network. Services injected via app.config.

Covers:
  1.  Success → 200 + token + user dict
  2.  Service absent → 404
  3.  IdentityProxyDisabledError → 404, generic message
  4.  IdentityProxyValidationError → 401, generic message
  5.  IdentityProxyUserError → 401, generic message
  6.  IdentityProxyConfigError → 503, generic message
  7.  Generic IdentityProxyError → 500, generic message
  8.  Aucune fuite de str(exc) dans la réponse
  9.  rate_limit_response appelé avec kind=identity_proxy_login

Run from project root:
    python3 scripts/tests/unit/test_auth_identity_proxy_routes.py
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask

from backend.models.user import User
from backend.routes_v2.auth_identity_proxy import auth_identity_proxy_v2_bp
from backend.services_v2.identity_proxy_validators.base import (
    IdentityProxyConfigError,
    IdentityProxyDisabledError,
    IdentityProxyError,
    IdentityProxyUserError,
    IdentityProxyValidationError,
)
from backend.services_v2.rate_limit_service import RateLimitResult
from backend.utils.time import utc_now_iso


# ── Fixtures ──────────────────────────────────────────────────────────────────

class _FakeSettings:
    DEBUG = True
    LINK2NAS_SINGLE_USER_MODE = False
    V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX = 20
    V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_WINDOW_SECONDS = 300


def _make_user() -> User:
    ts = utc_now_iso()
    return User(
        id="user-1",
        email="alice@example.com",
        display_name="Alice",
        role="user",
        is_active=True,
        created_at=ts,
        updated_at=ts,
        force_password_change=False,
    )


def _make_app(
    service=None,
    limiter=None,
    settings=None,
) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SETTINGS"] = settings or _FakeSettings()
    app.config["RATE_LIMIT_SERVICE_V2"] = limiter
    app.config["IDENTITY_PROXY_AUTH_SERVICE_V2"] = service
    app.config["APP_SETTINGS_SERVICE_V2"] = None
    app.register_blueprint(auth_identity_proxy_v2_bp)
    return app


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestLoginSuccess(unittest.TestCase):

    # 1. Success → 200 + token + user dict
    def test_success_returns_200_with_token_and_user(self):
        user = _make_user()
        svc = MagicMock()
        svc.authenticate.return_value = ("l2n_test_token_abc", user)

        resp = _make_app(service=svc).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["token"], "l2n_test_token_abc")
        self.assertIn("user", data)
        self.assertEqual(data["user"]["email"], "alice@example.com")
        self.assertIn("session_inactivity_minutes", data["user"])

    def test_user_dict_no_sensitive_fields(self):
        user = _make_user()
        svc = MagicMock()
        svc.authenticate.return_value = ("l2n_tok", user)

        data = _make_app(service=svc).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        ).get_json()
        self.assertNotIn("password_hash", data.get("user", {}))
        self.assertNotIn("email_verification_token", data.get("user", {}))
        self.assertNotIn("password_reset_token", data.get("user", {}))


class TestLoginServiceAbsent(unittest.TestCase):

    # 2. Service absent → 404
    def test_service_absent_returns_404(self):
        resp = _make_app(service=None).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        )
        self.assertEqual(resp.status_code, 404)


class TestLoginErrors(unittest.TestCase):

    def _test_error(self, exc, expected_status):
        svc = MagicMock()
        svc.authenticate.side_effect = exc
        resp = _make_app(service=svc).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        )
        self.assertEqual(resp.status_code, expected_status)
        return resp.get_json()

    # 3. IdentityProxyDisabledError → 404
    def test_disabled_error_returns_404(self):
        data = self._test_error(IdentityProxyDisabledError("disabled"), 404)
        self.assertIn("error", data)

    # 4. IdentityProxyValidationError → 401
    def test_validation_error_returns_401(self):
        data = self._test_error(IdentityProxyValidationError("bad token"), 401)
        self.assertIn("error", data)

    # 5. IdentityProxyUserError → 401
    def test_user_error_returns_401(self):
        data = self._test_error(IdentityProxyUserError("user disabled"), 401)
        self.assertIn("error", data)

    # 6. IdentityProxyConfigError → 503
    def test_config_error_returns_503(self):
        data = self._test_error(IdentityProxyConfigError("bad config"), 503)
        self.assertIn("error", data)

    # 7. Generic IdentityProxyError → 500
    def test_generic_error_returns_500(self):
        data = self._test_error(IdentityProxyError("unknown"), 500)
        self.assertIn("error", data)


class TestLoginNoLeaks(unittest.TestCase):

    def _make_sensitive_exc(self, exc_cls, secret: str):
        return exc_cls(f"SUPER_SECRET_INTERNAL_MSG:{secret}")

    # 8. Aucune fuite de str(exc) dans la réponse
    def test_no_leak_validation_error(self):
        secret = "JWT_TOKEN_XYZ_12345"
        svc = MagicMock()
        svc.authenticate.side_effect = IdentityProxyValidationError(
            f"Bad token: {secret}"
        )
        resp = _make_app(service=svc).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        )
        raw = resp.get_data(as_text=True)
        self.assertNotIn(secret, raw)

    def test_no_leak_user_error(self):
        secret = "internal_user_data_leak"
        svc = MagicMock()
        svc.authenticate.side_effect = IdentityProxyUserError(
            f"User lookup failed: {secret}"
        )
        resp = _make_app(service=svc).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        )
        raw = resp.get_data(as_text=True)
        self.assertNotIn(secret, raw)

    def test_no_leak_disabled_error(self):
        secret = "internal_disabled_reason"
        svc = MagicMock()
        svc.authenticate.side_effect = IdentityProxyDisabledError(
            f"Disabled because: {secret}"
        )
        resp = _make_app(service=svc).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        )
        raw = resp.get_data(as_text=True)
        self.assertNotIn(secret, raw)


class TestLoginRateLimit(unittest.TestCase):

    # 9. rate_limit_response appelé avec kind=identity_proxy_login
    def test_rate_limit_uses_identity_proxy_login_kind(self):
        user = _make_user()
        svc = MagicMock()
        svc.authenticate.return_value = ("l2n_tok", user)

        mock_limiter = MagicMock()
        mock_limiter.check.return_value = RateLimitResult(allowed=True, retry_after_seconds=0)

        app = _make_app(service=svc, limiter=mock_limiter)
        app.test_client().post("/api/v2/auth/identity-proxy/login")

        mock_limiter.check.assert_called_once()
        call_key = mock_limiter.check.call_args[0][0]
        self.assertTrue(
            call_key.startswith("identity_proxy_login:"),
            f"Expected key to start with 'identity_proxy_login:', got: {call_key}",
        )

    def test_rate_limit_exceeded_returns_429(self):
        mock_limiter = MagicMock()
        mock_limiter.check.return_value = RateLimitResult(allowed=False, retry_after_seconds=30)

        resp = _make_app(limiter=mock_limiter).test_client().post(
            "/api/v2/auth/identity-proxy/login"
        )
        self.assertEqual(resp.status_code, 429)


if __name__ == "__main__":
    unittest.main(verbosity=2)
