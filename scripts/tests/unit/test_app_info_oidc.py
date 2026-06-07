#!/usr/bin/env python3
"""
Unit tests: GET /api/v2/public/app-info — OIDC fields (DB-based, multi-provider).

Uses Flask test_client with fake services injected in app.config.
No real DB, no SMTP, no OIDC provider.

Covers:
  1.  No providers → oidc_enabled=false, oidc_label="", oidc_providers=[]
  2.  One provider → oidc_enabled=true, oidc_label set, oidc_providers has one entry
  3.  Multiple providers → oidc_enabled=true, all returned
  4.  Service returns filtered list (disabled hidden at service layer)
  5.  Single-user mode → oidc_enabled=false regardless of DB state
  6.  No sensitive fields in oidc_providers (only slug + button_label)
  7.  No OIDC_PROVIDER_SERVICE_V2 in config → graceful fallback (oidc_enabled=false)

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
    DEBUG = True
    LINK2NAS_SINGLE_USER_MODE = False
    APP_NAME = "Link2NAS"
    APP_TAGLINE = ""


class FakeSmtp:
    def is_email_sending_available(self):
        return False


class FakeOidcProviderService:
    def __init__(self, providers=None):
        self._providers = providers or []

    def list_public_enabled_providers(self, single_user_mode: bool):
        if single_user_mode:
            return []
        return self._providers


_P1 = {"slug": "keycloak", "button_label": "Sign in with Keycloak"}
_P2 = {"slug": "google", "button_label": "Sign in with Google"}


def _make_app(providers=None, *, single_user_mode: bool = False, omit_svc: bool = False) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    settings = FakeSettings()
    settings.LINK2NAS_SINGLE_USER_MODE = single_user_mode
    app.config["SETTINGS"] = settings
    app.config["SMTP_SERVICE_V2"] = FakeSmtp()
    app.config["APP_SETTINGS_SERVICE_V2"] = None

    if not omit_svc:
        app.config["OIDC_PROVIDER_SERVICE_V2"] = FakeOidcProviderService(providers or [])

    app.register_blueprint(public_tokens_v2_bp)
    return app


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAppInfoOidc(unittest.TestCase):

    # 1. No providers
    def test_no_providers_oidc_disabled(self):
        data = _make_app([]).test_client().get("/api/v2/public/app-info").get_json()
        self.assertFalse(data["oidc_enabled"])
        self.assertEqual(data["oidc_label"], "")
        self.assertEqual(data["oidc_providers"], [])

    # 2. One provider
    def test_one_provider_oidc_enabled(self):
        data = _make_app([_P1]).test_client().get("/api/v2/public/app-info").get_json()
        self.assertTrue(data["oidc_enabled"])
        self.assertEqual(data["oidc_label"], _P1["button_label"])
        self.assertEqual(len(data["oidc_providers"]), 1)
        self.assertEqual(data["oidc_providers"][0]["slug"], _P1["slug"])
        self.assertEqual(data["oidc_providers"][0]["button_label"], _P1["button_label"])

    # 3. Multiple providers all returned
    def test_multiple_providers_all_returned(self):
        data = _make_app([_P1, _P2]).test_client().get("/api/v2/public/app-info").get_json()
        self.assertTrue(data["oidc_enabled"])
        self.assertEqual(len(data["oidc_providers"]), 2)
        slugs = {p["slug"] for p in data["oidc_providers"]}
        self.assertIn("keycloak", slugs)
        self.assertIn("google", slugs)

    # 4. Service filters disabled; route reports based on what it receives
    def test_service_filters_disabled_providers(self):
        # Simulate service returning empty (all disabled)
        data = _make_app([]).test_client().get("/api/v2/public/app-info").get_json()
        self.assertFalse(data["oidc_enabled"])
        self.assertEqual(data["oidc_providers"], [])

    # 5. Single-user mode disables OIDC
    def test_single_user_mode_disables_oidc(self):
        data = _make_app([_P1, _P2], single_user_mode=True).test_client().get(
            "/api/v2/public/app-info"
        ).get_json()
        self.assertFalse(data["oidc_enabled"])
        self.assertEqual(data["oidc_providers"], [])

    # 6. Provider entries contain only slug and button_label — no sensitive fields
    def test_provider_entry_public_fields_only(self):
        data = _make_app([_P1]).test_client().get("/api/v2/public/app-info").get_json()
        entry = data["oidc_providers"][0]
        self.assertSetEqual(set(entry.keys()), {"slug", "button_label"})

        for field in ("issuer", "client_id", "client_secret", "encrypted_client_secret",
                      "scopes", "allowed_domains", "allowed_domains_json",
                      "auto_create_users", "id", "created_at", "updated_at"):
            self.assertNotIn(field, entry, f"Sensitive field '{field}' must not be in public entry")

    # 7. No OIDC_PROVIDER_SERVICE_V2 → graceful fallback
    def test_missing_service_falls_back_gracefully(self):
        data = _make_app(omit_svc=True).test_client().get("/api/v2/public/app-info").get_json()
        self.assertFalse(data["oidc_enabled"])
        self.assertEqual(data["oidc_label"], "")
        self.assertEqual(data["oidc_providers"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
