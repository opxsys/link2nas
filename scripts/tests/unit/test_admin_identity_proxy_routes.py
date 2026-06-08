#!/usr/bin/env python3
"""
Unit tests: /api/v2/admin/identity-proxy routes.

No real DB, no network. Auth mocked via fake token/user repos.

Covers:
  GET /config:
    1.  Super admin → 200 (no config → {enabled: false})
    2.  Super admin → 200 with config fields
    3.  No auth → 401
    4.  Regular user → 403

  PATCH /config:
    5.  Create (no existing config) → 200, config fields in response
    6.  Update (existing config) → 200
    7.  Validation error → 400

  POST /test:
    8.  No config → {ok: false}
    9.  Config present and valid → {ok: true}
    10. Config disabled → {ok: false}
    11. Missing team_domain → {ok: false}

  Security:
    12. Response never contains raw JWT, token, or client_secret fields

  Mutual exclusivity — Identity Proxy vs OIDC:
    13. Enable IP when OIDC providers are active → 409
    14. Enable IP when OIDC service is absent → 200 (check skipped)
    15. Disable IP (enabled=False) with active OIDC providers → 200 (no check)

Run from project root:
    python3 scripts/tests/unit/test_admin_identity_proxy_routes.py
"""

import json
import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask

from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.models.user import User
from backend.routes_v2.admin_identity_proxy import admin_identity_proxy_bp
from backend.services_v2.identity_proxy_config_service import IdentityProxyConfigService
from backend.services_v2.identity_proxy_validators.base import IdentityProxyConfigError
from backend.utils.time import utc_now_iso


# ── Constants ─────────────────────────────────────────────────────────────────

_SUPER_TOKEN = "tok-super-admin"
_USER_TOKEN = "tok-regular-user"
_CFG_JSON = json.dumps({"team_domain": "leang.cloudflareaccess.com", "audience": "aud-x"})


# ── Fakes ─────────────────────────────────────────────────────────────────────

class _FakeSettings:
    DEBUG = True
    LINK2NAS_SINGLE_USER_MODE = False


class _FakeApiToken:
    def __init__(self, user_id: str):
        self.user_id = user_id


class _FakeTokenRepo:
    def get_active_by_token(self, raw: str):
        if raw == _SUPER_TOKEN:
            return _FakeApiToken("user-super")
        if raw == _USER_TOKEN:
            return _FakeApiToken("user-regular")
        return None


def _make_user(uid: str, role: str = "user") -> User:
    ts = utc_now_iso()
    return User(
        id=uid, email=f"{uid}@example.com", display_name=uid,
        role=role, is_active=True, created_at=ts, updated_at=ts,
    )


class _FakeUserRepo:
    def get_by_id(self, uid: str):
        if uid == "user-super":
            return _make_user("user-super", role="super_admin")
        if uid == "user-regular":
            return _make_user("user-regular", role="user")
        return None


def _make_config(enabled: bool = True) -> IdentityProxyConfig:
    ts = utc_now_iso()
    return IdentityProxyConfig(
        id="cfg-1",
        name="CF Access",
        provider_type="cloudflare_access",
        enabled=enabled,
        label="Continue with Cloudflare Access",
        auto_login=False,
        auto_create_users=False,
        allowed_domains_json="[]",
        config_json=_CFG_JSON,
        created_at=ts,
        updated_at=ts,
    )


class _FakeConfigService:
    """Thin fake that stores one optional config and allows error injection."""

    create_raises = None
    update_raises = None

    def __init__(self, config: IdentityProxyConfig | None = None):
        self._config = config

    def get_first_config(self):
        return self._config

    def get_config_or_raise(self, config_id: str):
        if self._config and self._config.id == config_id:
            return self._config
        raise IdentityProxyConfigError("Not found")

    def create_config(self, **kwargs) -> IdentityProxyConfig:
        if self.create_raises:
            raise self.create_raises
        cfg = _make_config()
        self._config = cfg
        return cfg

    def update_config(self, config_id: str, **kwargs) -> IdentityProxyConfig:
        if self.update_raises:
            raise self.update_raises
        return self._config

    def to_admin_dict(self, config: IdentityProxyConfig) -> dict:
        return {
            "id": config.id,
            "name": config.name,
            "provider_type": config.provider_type,
            "enabled": config.enabled,
            "label": config.label,
            "auto_login": config.auto_login,
            "auto_create_users": config.auto_create_users,
            "allowed_domains_json": config.allowed_domains_json,
            "config_json": config.config_json,
            "created_at": config.created_at,
            "updated_at": config.updated_at,
        }


# ── Fake OIDC provider service (minimal, for mutex tests) ─────────────────────

class _FakeOidcProviderService:
    def __init__(self, has_enabled: bool = False):
        self._has_enabled = has_enabled

    def has_enabled_providers(self) -> bool:
        return self._has_enabled


# ── App factory ───────────────────────────────────────────────────────────────

def _make_app(svc=None, oidc_provider_svc=None) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SETTINGS"] = _FakeSettings()
    app.config["API_TOKEN_REPO_V2"] = _FakeTokenRepo()
    app.config["USER_REPO_V2"] = _FakeUserRepo()
    app.config["SINGLE_USER_SERVICE_V2"] = None
    app.config["IDENTITY_PROXY_CONFIG_SERVICE_V2"] = svc
    app.config["OIDC_PROVIDER_SERVICE_V2"] = oidc_provider_svc
    app.register_blueprint(admin_identity_proxy_bp)
    return app


def _auth(token: str = _SUPER_TOKEN) -> dict:
    return {"headers": {"X-Api-Key": token}}


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestGetConfig(unittest.TestCase):

    # 1. No config → {enabled: false}
    def test_get_config_no_config_returns_disabled(self):
        resp = _make_app(_FakeConfigService(None)).test_client().get(
            "/api/v2/admin/identity-proxy/config", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("enabled"))

    # 2. Config present → full dict with expected fields
    def test_get_config_returns_config_fields(self):
        resp = _make_app(_FakeConfigService(_make_config())).test_client().get(
            "/api/v2/admin/identity-proxy/config", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("id", data)
        self.assertIn("provider_type", data)
        self.assertIn("enabled", data)
        self.assertIn("label", data)
        self.assertIn("allowed_domains", data)
        self.assertIsInstance(data["allowed_domains"], list)
        self.assertIn("config", data)
        self.assertIsInstance(data["config"], dict)
        self.assertNotIn("allowed_domains_json", data)
        self.assertNotIn("config_json", data)

    # 3. No auth → 401
    def test_no_auth_returns_401(self):
        resp = _make_app().test_client().get(
            "/api/v2/admin/identity-proxy/config"
        )
        self.assertEqual(resp.status_code, 401)

    # 4. Regular user → 403
    def test_regular_user_returns_403(self):
        resp = _make_app().test_client().get(
            "/api/v2/admin/identity-proxy/config", **_auth(_USER_TOKEN)
        )
        self.assertEqual(resp.status_code, 403)


class TestPatchConfig(unittest.TestCase):

    # 5. Create (no existing config)
    def test_patch_creates_config_when_absent(self):
        svc = _FakeConfigService(None)
        resp = _make_app(svc).test_client().patch(
            "/api/v2/admin/identity-proxy/config",
            json={
                "provider_type": "cloudflare_access",
                "config": {"team_domain": "leang.cloudflareaccess.com", "audience": "a"},
                "enabled": True,
            },
            **_auth(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("id", data)

    # 6. Update (existing config)
    def test_patch_updates_existing_config(self):
        svc = _FakeConfigService(_make_config())
        resp = _make_app(svc).test_client().patch(
            "/api/v2/admin/identity-proxy/config",
            json={"enabled": False},
            **_auth(),
        )
        self.assertEqual(resp.status_code, 200)

    # 7. Validation error → 400
    def test_patch_validation_error_returns_400(self):
        svc = _FakeConfigService(None)
        svc.create_raises = IdentityProxyConfigError("Bad config")
        resp = _make_app(svc).test_client().patch(
            "/api/v2/admin/identity-proxy/config",
            json={"provider_type": "cloudflare_access", "config": {}},
            **_auth(),
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("error", data)


class TestPostTest(unittest.TestCase):

    # 8. No config → {ok: false}
    def test_test_no_config_returns_ok_false(self):
        resp = _make_app(_FakeConfigService(None)).test_client().post(
            "/api/v2/admin/identity-proxy/test", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("error", data)

    # 9. Config present and valid → {ok: true}
    def test_test_valid_config_returns_ok_true(self):
        resp = _make_app(_FakeConfigService(_make_config(enabled=True))).test_client().post(
            "/api/v2/admin/identity-proxy/test", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])

    # 10. Config disabled → {ok: false}
    def test_test_disabled_config_returns_ok_false(self):
        resp = _make_app(_FakeConfigService(_make_config(enabled=False))).test_client().post(
            "/api/v2/admin/identity-proxy/test", **_auth()
        )
        data = resp.get_json()
        self.assertFalse(data["ok"])

    # 11. Missing team_domain → {ok: false}
    def test_test_missing_team_domain_returns_ok_false(self):
        ts = utc_now_iso()
        cfg = IdentityProxyConfig(
            id="cfg-bad", name="CF", provider_type="cloudflare_access",
            enabled=True, label="CF", auto_login=False, auto_create_users=False,
            allowed_domains_json="[]",
            config_json=json.dumps({"audience": "aud-only"}),
            created_at=ts, updated_at=ts,
        )
        resp = _make_app(_FakeConfigService(cfg)).test_client().post(
            "/api/v2/admin/identity-proxy/test", **_auth()
        )
        data = resp.get_json()
        self.assertFalse(data["ok"])


class TestMutualExclusivity(unittest.TestCase):

    # 13. Enabling IP with active OIDC providers → 409
    def test_enable_ip_with_active_oidc_returns_409(self):
        oidc_svc = _FakeOidcProviderService(has_enabled=True)
        resp = _make_app(
            svc=_FakeConfigService(None),
            oidc_provider_svc=oidc_svc,
        ).test_client().patch(
            "/api/v2/admin/identity-proxy/config",
            json={"provider_type": "cloudflare_access", "enabled": True,
                  "config": {"team_domain": "x.cloudflareaccess.com", "audience": "a"}},
            **_auth(),
        )
        self.assertEqual(resp.status_code, 409)
        data = resp.get_json()
        self.assertIn("error", data)
        self.assertIn("OIDC", data["error"])

    # 14. Enabling IP with no OIDC service present → 200 (check skipped)
    def test_enable_ip_without_oidc_service_succeeds(self):
        resp = _make_app(
            svc=_FakeConfigService(None),
            oidc_provider_svc=None,
        ).test_client().patch(
            "/api/v2/admin/identity-proxy/config",
            json={"provider_type": "cloudflare_access", "enabled": True,
                  "config": {"team_domain": "x.cloudflareaccess.com", "audience": "a"}},
            **_auth(),
        )
        self.assertEqual(resp.status_code, 200)

    # 15. Disabling IP (enabled=False) with active OIDC → 200 (no check triggered)
    def test_disable_ip_with_active_oidc_allowed(self):
        oidc_svc = _FakeOidcProviderService(has_enabled=True)
        resp = _make_app(
            svc=_FakeConfigService(_make_config(enabled=True)),
            oidc_provider_svc=oidc_svc,
        ).test_client().patch(
            "/api/v2/admin/identity-proxy/config",
            json={"enabled": False},
            **_auth(),
        )
        self.assertEqual(resp.status_code, 200)


class TestAdminSecurity(unittest.TestCase):

    # 12. No raw token/JWT/secret in GET response
    def test_no_sensitive_fields_in_get_response(self):
        resp = _make_app(_FakeConfigService(_make_config())).test_client().get(
            "/api/v2/admin/identity-proxy/config", **_auth()
        )
        raw = resp.get_data(as_text=True)
        for forbidden in ("client_secret", "jwt", "bearer", "password_hash"):
            self.assertNotIn(forbidden, raw.lower())

    def test_no_raw_config_json_exposed(self):
        data = _make_app(_FakeConfigService(_make_config())).test_client().get(
            "/api/v2/admin/identity-proxy/config", **_auth()
        ).get_json()
        self.assertNotIn("config_json", data)
        self.assertNotIn("allowed_domains_json", data)
        self.assertIsInstance(data.get("config"), dict)
        self.assertIsInstance(data.get("allowed_domains"), list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
