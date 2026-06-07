#!/usr/bin/env python3
"""
Unit tests: OIDC rate-limit entries in the anti-abuse endpoint.

Covers:
  1.  OIDC kinds present in KNOWN_ANTI_ABUSE_KINDS registry
  2.  OIDC entries carry single_user_hidden=True
  3.  OIDC config attributes exist in config.py defaults (via getattr fallback)
  4.  GET /anti-abuse — multi-user mode: OIDC kinds present in response
  5.  GET /anti-abuse — single-user mode: OIDC kinds absent from response
  6.  GET /anti-abuse — non-OIDC kinds still present in single-user mode
  7.  POST /anti-abuse/reset/oidc_initiate — valid kind, super admin → 200

Run from project root:
    python3 scripts/tests/unit/test_anti_abuse_oidc.py
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
from backend.services_v2.rate_limit_service import (
    KNOWN_ANTI_ABUSE_KINDS,
    RateLimitService,
)
from backend.utils.time import utc_now_iso


# ── Constants ─────────────────────────────────────────────────────────────────

_SUPER_TOKEN = "tok-superadmin-aabuse"
_OIDC_KINDS = {"oidc_initiate", "oidc_callback", "oidc_complete"}


# ── Fake auth ─────────────────────────────────────────────────────────────────

class _FakeApiToken:
    def __init__(self, user_id: str):
        self.user_id = user_id


class _FakeTokenRepo:
    def get_active_by_token(self, raw: str):
        if raw == _SUPER_TOKEN:
            return _FakeApiToken("user-super")
        return None


def _make_user(uid: str, role: str = "super_admin") -> User:
    ts = utc_now_iso()
    return User(
        id=uid,
        email=f"{uid}@example.com",
        display_name=uid,
        role=role,
        is_active=True,
        created_at=ts,
        updated_at=ts,
    )


class _FakeUserRepo:
    def get_by_id(self, uid: str):
        if uid == "user-super":
            return _make_user("user-super", role="super_admin")
        return None


class _FakeSingleUserService:
    """Single-user mode: always returns a super_admin user (no API key needed)."""
    def get_or_create_single_user(self):
        return _make_user("user-single", role="super_admin")


# ── App factory ───────────────────────────────────────────────────────────────

class _FakeSettings:
    DEBUG = True
    REDIS_URL = ""
    V2_RATE_LIMIT_OIDC_INITIATE_MAX = 20
    V2_RATE_LIMIT_OIDC_INITIATE_WINDOW_SECONDS = 300
    V2_RATE_LIMIT_OIDC_CALLBACK_MAX = 30
    V2_RATE_LIMIT_OIDC_CALLBACK_WINDOW_SECONDS = 300
    V2_RATE_LIMIT_OIDC_COMPLETE_MAX = 20
    V2_RATE_LIMIT_OIDC_COMPLETE_WINDOW_SECONDS = 300


class _FakeSettingsSingleUser(_FakeSettings):
    LINK2NAS_SINGLE_USER_MODE = True


class _FakeSettingsMultiUser(_FakeSettings):
    LINK2NAS_SINGLE_USER_MODE = False


def _make_app(*, single_user: bool = False) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SETTINGS"] = _FakeSettingsSingleUser() if single_user else _FakeSettingsMultiUser()
    app.config["API_TOKEN_REPO_V2"] = _FakeTokenRepo()
    app.config["USER_REPO_V2"] = _FakeUserRepo()
    app.config["SINGLE_USER_SERVICE_V2"] = _FakeSingleUserService()
    app.config["RATE_LIMIT_SERVICE_V2"] = RateLimitService(enabled=True)
    app.register_blueprint(admin_security_v2_bp)
    return app


def _auth() -> dict:
    return {"headers": {"X-Api-Key": _SUPER_TOKEN}}


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestOidcRegistryEntries(unittest.TestCase):

    # 1. All three OIDC kinds are present in the registry
    def test_oidc_kinds_in_known_registry(self):
        known = {m["kind"] for m in KNOWN_ANTI_ABUSE_KINDS}
        self.assertTrue(_OIDC_KINDS.issubset(known), f"Missing OIDC kinds: {_OIDC_KINDS - known}")

    # 2. OIDC entries carry single_user_hidden=True
    def test_oidc_entries_are_single_user_hidden(self):
        oidc_entries = [m for m in KNOWN_ANTI_ABUSE_KINDS if m["kind"] in _OIDC_KINDS]
        for entry in oidc_entries:
            self.assertTrue(
                entry.get("single_user_hidden"),
                f"{entry['kind']} should have single_user_hidden=True",
            )

    # 3. Entries that are always visible (not tied to multi-user auth) must not be hidden
    def test_non_auth_entries_not_single_user_hidden(self):
        always_visible = {"login", "qbittorrent_add", "token_status"}
        for entry in KNOWN_ANTI_ABUSE_KINDS:
            if entry["kind"] in always_visible:
                self.assertFalse(
                    entry.get("single_user_hidden"),
                    f"{entry['kind']} should not have single_user_hidden=True",
                )


class TestAntiAbuseOidcFiltering(unittest.TestCase):

    # 4. Multi-user: OIDC kinds visible in response
    def test_multi_user_oidc_kinds_present(self):
        resp = _make_app(single_user=False).test_client().get(
            "/api/v2/admin/security/anti-abuse", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        kinds = {c["kind"] for c in data["counters"]}
        self.assertTrue(_OIDC_KINDS.issubset(kinds), f"Expected OIDC kinds, got: {kinds}")

    # 5. Single-user: OIDC kinds absent from response (no API key needed in single-user mode)
    def test_single_user_oidc_kinds_absent(self):
        resp = _make_app(single_user=True).test_client().get(
            "/api/v2/admin/security/anti-abuse"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        kinds = {c["kind"] for c in data["counters"]}
        overlap = _OIDC_KINDS & kinds
        self.assertFalse(overlap, f"OIDC kinds should be hidden in single-user mode, found: {overlap}")

    # 6. Single-user: non-OIDC counter (qbittorrent_add) still present
    def test_single_user_non_oidc_kind_present(self):
        resp = _make_app(single_user=True).test_client().get(
            "/api/v2/admin/security/anti-abuse"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        kinds = {c["kind"] for c in data["counters"]}
        self.assertIn("qbittorrent_add", kinds)


class TestAntiAbuseOidcReset(unittest.TestCase):

    # 7. Reset oidc_initiate — valid kind → 200
    def test_reset_oidc_initiate_kind(self):
        resp = _make_app(single_user=False).test_client().post(
            "/api/v2/admin/security/anti-abuse/reset/oidc_initiate", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("kind"), "oidc_initiate")


if __name__ == "__main__":
    unittest.main()
