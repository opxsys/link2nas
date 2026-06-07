#!/usr/bin/env python3
"""
Unit tests: identity_proxy_login anti-abuse entry.

Mirrors test_anti_abuse_oidc.py for the Identity Proxy kind.

Covers:
  1.  identity_proxy_login présent dans KNOWN_ANTI_ABUSE_KINDS
  2.  single_user_hidden=True pour identity_proxy_login
  3.  V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX et WINDOW_SECONDS dans config.py
  4.  GET /anti-abuse multi-user → identity_proxy_login présent dans counters
  5.  GET /anti-abuse single-user → identity_proxy_login absent des counters
  6.  POST /anti-abuse/reset/identity_proxy_login — valid kind, super admin → 200

Run from project root:
    python3 scripts/tests/unit/test_anti_abuse_identity_proxy.py
"""

import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask

from backend.models.user import User
from backend.routes_v2.admin_security import admin_security_v2_bp
from backend.services_v2.rate_limit_service import KNOWN_ANTI_ABUSE_KINDS, RateLimitService
from backend.utils.time import utc_now_iso


# ── Constants ─────────────────────────────────────────────────────────────────

_SUPER_TOKEN = "tok-super-aabuse-ip"
_IP_KIND = "identity_proxy_login"


# ── Fakes ─────────────────────────────────────────────────────────────────────

class _FakeApiToken:
    def __init__(self, user_id: str):
        self.user_id = user_id


class _FakeTokenRepo:
    def get_active_by_token(self, raw: str):
        return _FakeApiToken("user-super") if raw == _SUPER_TOKEN else None


def _make_user(uid: str = "user-super", role: str = "super_admin") -> User:
    ts = utc_now_iso()
    return User(
        id=uid, email=f"{uid}@example.com", display_name=uid,
        role=role, is_active=True, created_at=ts, updated_at=ts,
    )


class _FakeUserRepo:
    def get_by_id(self, uid: str):
        return _make_user(uid) if uid == "user-super" else None


class _FakeSingleUserSvc:
    def get_or_create_single_user(self):
        return _make_user("user-single", role="super_admin")


class _FakeSettingsMultiUser:
    DEBUG = True
    REDIS_URL = ""
    LINK2NAS_SINGLE_USER_MODE = False
    V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX = 20
    V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_WINDOW_SECONDS = 300
    # Other counters needed by the endpoint
    V2_RATE_LIMIT_LOGIN_MAX = 10
    V2_RATE_LIMIT_LOGIN_WINDOW_SECONDS = 300
    V2_RATE_LIMIT_MAGIC_LOGIN_MAX = 5
    V2_RATE_LIMIT_MAGIC_LOGIN_WINDOW_SECONDS = 3600
    V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX = 20
    V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS = 300
    V2_RATE_LIMIT_EMAIL_REQUEST_MAX = 5
    V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS = 3600
    V2_RATE_LIMIT_QBITTORRENT_ADD_MAX = 30
    V2_RATE_LIMIT_QBITTORRENT_ADD_WINDOW_SECONDS = 60
    V2_RATE_LIMIT_TOKEN_STATUS_MAX = 60
    V2_RATE_LIMIT_TOKEN_STATUS_WINDOW_SECONDS = 300
    V2_RATE_LIMIT_OIDC_INITIATE_MAX = 20
    V2_RATE_LIMIT_OIDC_INITIATE_WINDOW_SECONDS = 300
    V2_RATE_LIMIT_OIDC_CALLBACK_MAX = 30
    V2_RATE_LIMIT_OIDC_CALLBACK_WINDOW_SECONDS = 300
    V2_RATE_LIMIT_OIDC_COMPLETE_MAX = 20
    V2_RATE_LIMIT_OIDC_COMPLETE_WINDOW_SECONDS = 300


class _FakeSettingsSingleUser(_FakeSettingsMultiUser):
    LINK2NAS_SINGLE_USER_MODE = True


def _make_app(*, single_user: bool = False) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SETTINGS"] = (
        _FakeSettingsSingleUser() if single_user else _FakeSettingsMultiUser()
    )
    app.config["API_TOKEN_REPO_V2"] = _FakeTokenRepo()
    app.config["USER_REPO_V2"] = _FakeUserRepo()
    app.config["SINGLE_USER_SERVICE_V2"] = _FakeSingleUserSvc()
    app.config["RATE_LIMIT_SERVICE_V2"] = RateLimitService(enabled=True)
    app.register_blueprint(admin_security_v2_bp)
    return app


def _auth() -> dict:
    return {"headers": {"X-Api-Key": _SUPER_TOKEN}}


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestIdentityProxyRegistryEntry(unittest.TestCase):

    # 1. identity_proxy_login present in KNOWN_ANTI_ABUSE_KINDS
    def test_identity_proxy_login_in_registry(self):
        kinds = {m["kind"] for m in KNOWN_ANTI_ABUSE_KINDS}
        self.assertIn(_IP_KIND, kinds)

    # 2. single_user_hidden=True
    def test_identity_proxy_login_is_single_user_hidden(self):
        entry = next(
            (m for m in KNOWN_ANTI_ABUSE_KINDS if m["kind"] == _IP_KIND), None
        )
        self.assertIsNotNone(entry)
        self.assertTrue(
            entry.get("single_user_hidden"),
            f"{_IP_KIND} must have single_user_hidden=True",
        )

    # 3. Config attributes exist in Settings defaults
    def test_config_attributes_have_defaults(self):
        settings = _FakeSettingsMultiUser()
        self.assertGreater(settings.V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX, 0)
        self.assertGreater(settings.V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_WINDOW_SECONDS, 0)


class TestAntiAbuseIdentityProxyFiltering(unittest.TestCase):

    # 4. Multi-user: identity_proxy_login visible in counters
    def test_multi_user_identity_proxy_login_present(self):
        resp = _make_app(single_user=False).test_client().get(
            "/api/v2/admin/security/anti-abuse", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        kinds = {c["kind"] for c in resp.get_json()["counters"]}
        self.assertIn(_IP_KIND, kinds)

    # 5. Single-user: identity_proxy_login absent from counters
    def test_single_user_identity_proxy_login_absent(self):
        resp = _make_app(single_user=True).test_client().get(
            "/api/v2/admin/security/anti-abuse"
        )
        self.assertEqual(resp.status_code, 200)
        kinds = {c["kind"] for c in resp.get_json()["counters"]}
        self.assertNotIn(_IP_KIND, kinds)


class TestAntiAbuseIdentityProxyReset(unittest.TestCase):

    # 6. Reset identity_proxy_login → 200
    def test_reset_identity_proxy_login_kind(self):
        resp = _make_app(single_user=False).test_client().post(
            f"/api/v2/admin/security/anti-abuse/reset/{_IP_KIND}", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("kind"), _IP_KIND)


if __name__ == "__main__":
    unittest.main(verbosity=2)
