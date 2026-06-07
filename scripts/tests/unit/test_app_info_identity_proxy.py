#!/usr/bin/env python3
"""
Unit tests: GET /api/v2/public/app-info — Identity Proxy fields.

No real DB, no network. Services injected via app.config.

Covers:
  1.  No auth service → identity_proxy_enabled=false, all fields present
  2.  Auth service present, config enabled → identity_proxy_enabled=true + fields
  3.  Single-user mode → identity_proxy_enabled=false regardless of service
  4.  Config disabled → identity_proxy_enabled=false
  5.  No sensitive fields in response (no team_domain, audience, allowed_domains)
  6.  identity_proxy_label defaults to "" when disabled
  7.  identity_proxy_auto_login reflects service value
  8.  identity_proxy_provider_type reflects service value

Run from project root:
    python3 scripts/tests/unit/test_app_info_identity_proxy.py
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

class _FakeSettings:
    DEBUG = True
    APP_NAME = "Link2NAS"
    APP_TAGLINE = ""
    LINK2NAS_SINGLE_USER_MODE = False


class _FakeSmtp:
    def is_email_sending_available(self):
        return False


class _FakeOidcProviderSvc:
    def list_public_enabled_providers(self, single_user_mode):
        return []


class _FakeIdentityProxyAuthSvc:
    def __init__(self, status: dict):
        self._status = status

    def get_public_status(self, single_user_mode: bool) -> dict:
        if single_user_mode:
            return {"enabled": False}
        return self._status


def _make_app(
    ip_svc=None,
    *,
    single_user_mode: bool = False,
) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    settings = _FakeSettings()
    settings.LINK2NAS_SINGLE_USER_MODE = single_user_mode
    app.config["SETTINGS"] = settings
    app.config["SMTP_SERVICE_V2"] = _FakeSmtp()
    app.config["APP_SETTINGS_SERVICE_V2"] = None
    app.config["OIDC_PROVIDER_SERVICE_V2"] = _FakeOidcProviderSvc()
    app.config["IDENTITY_PROXY_AUTH_SERVICE_V2"] = ip_svc
    app.register_blueprint(public_tokens_v2_bp)
    return app


def _get_info(ip_svc=None, *, single_user_mode: bool = False) -> dict:
    return (
        _make_app(ip_svc, single_user_mode=single_user_mode)
        .test_client()
        .get("/api/v2/public/app-info")
        .get_json()
    )


_ENABLED_STATUS = {
    "enabled": True,
    "provider_type": "cloudflare_access",
    "label": "Continue with Cloudflare Access",
    "auto_login": True,
}


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAppInfoIdentityProxyDisabled(unittest.TestCase):

    # 1. No service → disabled fields present with safe defaults
    def test_no_service_identity_proxy_disabled(self):
        data = _get_info(ip_svc=None)
        self.assertFalse(data["identity_proxy_enabled"])
        self.assertEqual(data["identity_proxy_label"], "")
        self.assertFalse(data["identity_proxy_auto_login"])
        self.assertEqual(data["identity_proxy_provider_type"], "")

    # 4. Config disabled → disabled fields
    def test_disabled_status_returns_disabled(self):
        svc = _FakeIdentityProxyAuthSvc({"enabled": False})
        data = _get_info(ip_svc=svc)
        self.assertFalse(data["identity_proxy_enabled"])

    # 3. Single-user mode → disabled
    def test_single_user_mode_disables_identity_proxy(self):
        svc = _FakeIdentityProxyAuthSvc(_ENABLED_STATUS)
        data = _get_info(ip_svc=svc, single_user_mode=True)
        self.assertFalse(data["identity_proxy_enabled"])
        self.assertEqual(data["identity_proxy_label"], "")

    # 6. Label defaults to "" when disabled
    def test_label_empty_when_disabled(self):
        data = _get_info(ip_svc=None)
        self.assertEqual(data["identity_proxy_label"], "")


class TestAppInfoIdentityProxyEnabled(unittest.TestCase):

    # 2. Enabled → all public fields present and correct
    def test_enabled_status_returns_correct_fields(self):
        svc = _FakeIdentityProxyAuthSvc(_ENABLED_STATUS)
        data = _get_info(ip_svc=svc)
        self.assertTrue(data["identity_proxy_enabled"])
        self.assertEqual(data["identity_proxy_label"], "Continue with Cloudflare Access")
        self.assertTrue(data["identity_proxy_auto_login"])
        self.assertEqual(data["identity_proxy_provider_type"], "cloudflare_access")

    # 7. auto_login reflects service value
    def test_auto_login_reflects_service(self):
        svc = _FakeIdentityProxyAuthSvc({**_ENABLED_STATUS, "auto_login": False})
        data = _get_info(ip_svc=svc)
        self.assertFalse(data["identity_proxy_auto_login"])

    # 8. provider_type reflects service value
    def test_provider_type_reflects_service(self):
        svc = _FakeIdentityProxyAuthSvc(_ENABLED_STATUS)
        data = _get_info(ip_svc=svc)
        self.assertEqual(data["identity_proxy_provider_type"], "cloudflare_access")


class TestAppInfoIdentityProxySecurity(unittest.TestCase):

    # 5. No sensitive fields exposed
    def test_no_sensitive_fields_in_enabled_response(self):
        svc = _FakeIdentityProxyAuthSvc(_ENABLED_STATUS)
        data = _get_info(ip_svc=svc)
        forbidden = {
            "team_domain", "audience", "allowed_domains", "allowed_domains_json",
            "config_json", "config", "auto_create_users",
        }
        exposed = forbidden & set(data.keys())
        self.assertFalse(exposed, f"Sensitive fields exposed: {exposed}")

    def test_no_sensitive_fields_in_disabled_response(self):
        data = _get_info(ip_svc=None)
        forbidden = {"team_domain", "audience", "config_json", "allowed_domains_json"}
        exposed = forbidden & set(data.keys())
        self.assertFalse(exposed, f"Sensitive fields exposed: {exposed}")

    # All expected identity_proxy_* keys present
    def test_all_identity_proxy_keys_present(self):
        data = _get_info(ip_svc=None)
        for key in (
            "identity_proxy_enabled",
            "identity_proxy_label",
            "identity_proxy_auto_login",
            "identity_proxy_provider_type",
        ):
            self.assertIn(key, data, f"Missing key: {key}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
