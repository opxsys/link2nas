#!/usr/bin/env python3
"""
Unit tests: GET /api/v2/public/app-info — OIDC fields.

Uses Flask test_client with fake settings injected in app.config.
No real DB, no SMTP, no OIDC provider.

Covers:
  1. OIDC_ENABLED=False → oidc_enabled=False, oidc_label=""
  2. OIDC_ENABLED=True → oidc_enabled=True, oidc_label=OIDC_BUTTON_LABEL
  3. OIDC_ENABLED=True + LINK2NAS_SINGLE_USER_MODE=True → oidc_enabled=False, oidc_label=""
  4. Response never exposes OIDC internals (CLIENT_ID, CLIENT_SECRET, ISSUER,
     SCOPES, ALLOWED_DOMAINS, AUTO_CREATE_USERS)

Run from project root:
    python3 scripts/tests/unit/test_app_info_oidc.py
"""

import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask
from backend.routes_v2.public_tokens import public_tokens_v2_bp


# ── Fakes ─────────────────────────────────────────────────────────────────────

class FakeSettings:
    APP_NAME = "TestApp"
    APP_TAGLINE = ""
    OIDC_ENABLED = False
    OIDC_BUTTON_LABEL = "Sign in with SSO"
    LINK2NAS_SINGLE_USER_MODE = False
    # Internal values that must never appear in the API response
    OIDC_CLIENT_ID = "fake-client-id-abc123"
    OIDC_CLIENT_SECRET = "fake-client-secret-xyz"
    OIDC_ISSUER = "https://idp.internal.example.com"
    OIDC_SCOPES = "openid email profile"
    OIDC_ALLOWED_DOMAINS = "restricted.example.com"
    OIDC_AUTO_CREATE_USERS = True


def _make_app(settings: FakeSettings) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SETTINGS"] = settings
    app.config["SMTP_SERVICE_V2"] = None
    app.config["APP_SETTINGS_SERVICE_V2"] = None
    app.register_blueprint(public_tokens_v2_bp)
    return app


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAppInfoOidc(unittest.TestCase):

    # 1. OIDC_ENABLED=False → oidc_enabled=False, oidc_label=""
    def test_oidc_disabled_returns_false_and_empty_label(self):
        settings = FakeSettings()
        settings.OIDC_ENABLED = False
        resp = _make_app(settings).test_client().get("/api/v2/public/app-info")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["oidc_enabled"], "oidc_enabled must be false when OIDC_ENABLED=False")
        self.assertEqual(data["oidc_label"], "", "oidc_label must be empty when OIDC disabled")

    # 2. OIDC_ENABLED=True → oidc_enabled=True, oidc_label=OIDC_BUTTON_LABEL
    def test_oidc_enabled_returns_true_and_configured_label(self):
        settings = FakeSettings()
        settings.OIDC_ENABLED = True
        settings.LINK2NAS_SINGLE_USER_MODE = False
        settings.OIDC_BUTTON_LABEL = "Se connecter via Keycloak"
        resp = _make_app(settings).test_client().get("/api/v2/public/app-info")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["oidc_enabled"], "oidc_enabled must be true when OIDC_ENABLED=True")
        self.assertEqual(data["oidc_label"], "Se connecter via Keycloak")

    # 3. OIDC_ENABLED=True + LINK2NAS_SINGLE_USER_MODE=True → oidc_enabled=False, oidc_label=""
    def test_oidc_disabled_in_single_user_mode(self):
        settings = FakeSettings()
        settings.OIDC_ENABLED = True
        settings.LINK2NAS_SINGLE_USER_MODE = True
        settings.OIDC_BUTTON_LABEL = "Sign in with SSO"
        resp = _make_app(settings).test_client().get("/api/v2/public/app-info")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["oidc_enabled"], "oidc_enabled must be false in single-user mode")
        self.assertEqual(data["oidc_label"], "", "oidc_label must be empty in single-user mode")

    # 4. Response never exposes OIDC internals
    def test_no_oidc_internals_in_response(self):
        settings = FakeSettings()
        settings.OIDC_ENABLED = True
        settings.LINK2NAS_SINGLE_USER_MODE = False
        resp = _make_app(settings).test_client().get("/api/v2/public/app-info")
        self.assertEqual(resp.status_code, 200)

        # Check JSON keys — only these five are allowed
        data = resp.get_json()
        allowed_keys = {"app_name", "app_tagline", "email_sending_available", "oidc_enabled", "oidc_label"}
        self.assertEqual(set(data.keys()), allowed_keys, f"Unexpected keys in response: {set(data.keys()) - allowed_keys}")

        # Check raw body for sensitive values
        raw = resp.get_data(as_text=True)
        for forbidden in [
            settings.OIDC_CLIENT_ID,
            settings.OIDC_CLIENT_SECRET,
            settings.OIDC_ISSUER,
            settings.OIDC_SCOPES,
            settings.OIDC_ALLOWED_DOMAINS,
        ]:
            self.assertNotIn(forbidden, raw, f"Sensitive value must not appear in response: {forbidden!r}")

        # Check forbidden field names are not present as JSON keys
        for forbidden_key in ("client_id", "client_secret", "issuer", "scopes",
                              "allowed_domains", "auto_create_users"):
            self.assertNotIn(forbidden_key, data, f"Field {forbidden_key!r} must not be in response")


if __name__ == "__main__":
    unittest.main(verbosity=2)
