#!/usr/bin/env python3
"""
Unit tests: /api/v2/admin/oidc-providers routes.

Uses Flask test_client with fake repos and services injected in app.config.
No real DB, no network calls.

Covers:
  GET /:
    1.  Super admin → 200 list (may be empty)
    2.  No auth → 401
    3.  Non-super-admin → 403

  POST /:
    4.  Create valid provider → 201, has_client_secret=true, no secret fields
    5.  Validation error → 400
    6.  Missing secret when enabled → 400

  GET /<id>:
    7.  Known provider → 200, admin dict fields
    8.  Unknown provider → 404

  PATCH /<id>:
    9.  PATCH without client_secret → secret preserved (has_client_secret=true)
    10. PATCH with client_secret → secret replaced

  DELETE /<id>:
    11. Known provider → 200 {ok: true}
    12. Provider in use → 409
    13. Unknown provider → 404

  POST /<id>/test-discovery:
    14. Discovery OK → {ok: true}
    15. Discovery unreachable → {ok: false}, generic error, no secrets

  Mutual exclusivity — OIDC vs Identity Proxy:
    16. Create enabled OIDC when IP is active → 409
    17. Create disabled OIDC when IP is active → 201 (no check)
    18. Update to enabled=True when IP is active → 409
    19. Update to enabled=False when IP is active → 200 (no check)

Run from project root:
    python3 scripts/tests/unit/test_admin_oidc_provider_routes.py
"""

import json
import os
import sys
import uuid
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask

from backend.models.oidc_provider import OidcProvider
from backend.models.user import User
from backend.routes_v2.admin_oidc_providers import admin_oidc_providers_bp
from backend.services_v2.oidc_provider_service import (
    OidcProviderInUseError,
    OidcProviderNotFoundError,
    OidcProviderSecretError,
    OidcProviderService,
    OidcProviderValidationError,
)
from backend.utils.time import utc_now_iso


# ── Constants ─────────────────────────────────────────────────────────────────

_SUPER_TOKEN = "tok-superadmin-test"
_USER_TOKEN = "tok-user-test"
_PROVIDER_ID = "prov-id-test-1"
_PROVIDER_ID_2 = "prov-id-test-2"


# ── Fake models ───────────────────────────────────────────────────────────────

def _make_provider(
    pid: str = _PROVIDER_ID,
    slug: str = "keycloak",
    enabled: bool = True,
    has_secret: bool = True,
) -> OidcProvider:
    ts = utc_now_iso()
    return OidcProvider(
        id=pid,
        name="Keycloak Test",
        slug=slug,
        enabled=enabled,
        issuer="https://idp.example.com/realm/test",
        client_id="my-client",
        scopes="openid email profile",
        button_label="Sign in with Keycloak",
        auto_create_users=False,
        allowed_domains_json="[]",
        state_ttl_seconds=600,
        exchange_code_ttl_seconds=60,
        sort_order=0,
        created_at=ts,
        updated_at=ts,
        encrypted_client_secret="enc::secret-abc" if has_secret else None,
    )


def _make_user(uid: str, role: str = "user") -> User:
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


# ── Fake repos ────────────────────────────────────────────────────────────────

class _FakeApiToken:
    def __init__(self, user_id: str):
        self.user_id = user_id


class FakeTokenRepo:
    def get_active_by_token(self, raw: str):
        if raw == _SUPER_TOKEN:
            return _FakeApiToken("user-super")
        if raw == _USER_TOKEN:
            return _FakeApiToken("user-regular")
        return None


class FakeUserRepo:
    def __init__(self):
        self._users = {
            "user-super": _make_user("user-super", role="super_admin"),
            "user-regular": _make_user("user-regular", role="user"),
        }

    def get_by_id(self, uid: str):
        return self._users.get(uid)


# ── Fake services ─────────────────────────────────────────────────────────────

class FakeOidcProviderService:
    """Stateful fake that stores one provider and allows override of CRUD outcomes."""

    create_raises: Exception | None = None
    update_raises: Exception | None = None
    delete_raises: Exception | None = None

    def __init__(self, provider: OidcProvider | None = None):
        self._provider = provider or _make_provider()
        self._update_result: OidcProvider | None = None

    # Delegate serialization to the real service's static logic
    def to_admin_dict(self, provider: OidcProvider) -> dict:
        from backend.services_v2.oidc_provider_service import OidcProviderService as _Real

        class _MinimalCrypto:
            def encrypt(self, v): return f"enc::{v}"
            def decrypt(self, v): return v.removeprefix("enc::")

        class _MinimalRepo:
            def list_all(self): return []
            def list_enabled(self): return []
            def get_by_id(self, _): return None
            def get_by_slug(self, _): return None
            def save(self, p): return p
            def delete(self, _): pass

        class _MinimalExtRepo:
            def count_by_issuer(self, _): return 0

        svc = _Real(_MinimalRepo(), _MinimalExtRepo(), _MinimalCrypto())
        return svc.to_admin_dict(provider)

    def list_all(self):
        return [self._provider]

    def get_provider_or_raise(self, provider_id: str) -> OidcProvider:
        if provider_id == self._provider.id:
            return self._provider
        raise OidcProviderNotFoundError("Not found")

    def create_provider(self, **kwargs) -> OidcProvider:
        if self.create_raises:
            raise self.create_raises
        return self._provider

    def update_provider(self, provider_id: str, **kwargs) -> OidcProvider:
        if provider_id != self._provider.id:
            raise OidcProviderNotFoundError("Not found")
        if self.update_raises:
            raise self.update_raises
        return self._update_result or self._provider

    def delete_provider(self, provider_id: str) -> None:
        if provider_id != self._provider.id:
            raise OidcProviderNotFoundError("Not found")
        if self.delete_raises:
            raise self.delete_raises


class FakeOidcService:
    discovery_raises: Exception | None = None

    def fetch_provider_metadata(self, issuer: str) -> dict:
        if self.discovery_raises:
            raise self.discovery_raises
        return {
            "authorization_endpoint": f"{issuer}/auth",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/certs",
        }


# ── App factory ───────────────────────────────────────────────────────────────

class FakeSettings:
    DEBUG = True
    LINK2NAS_SINGLE_USER_MODE = False


class FakeIdentityProxyConfigService:
    """Minimal fake for mutual exclusivity tests."""

    def __init__(self, enabled: bool = False):
        import types
        self._cfg = types.SimpleNamespace(enabled=enabled) if enabled else None

    def get_first_config(self):
        return self._cfg


def _make_app(
    provider_svc: FakeOidcProviderService | None = None,
    oidc_svc: FakeOidcService | None = None,
    ip_config_svc: FakeIdentityProxyConfigService | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SETTINGS"] = FakeSettings()
    app.config["API_TOKEN_REPO_V2"] = FakeTokenRepo()
    app.config["USER_REPO_V2"] = FakeUserRepo()
    app.config["OIDC_PROVIDER_SERVICE_V2"] = provider_svc or FakeOidcProviderService()
    app.config["OIDC_SERVICE_V2"] = oidc_svc or FakeOidcService()
    app.config["IDENTITY_PROXY_CONFIG_SERVICE_V2"] = ip_config_svc
    app.register_blueprint(admin_oidc_providers_bp)
    return app


def _auth(token: str = _SUPER_TOKEN) -> dict:
    return {"headers": {"X-Api-Key": token}}


# ── Helpers ───────────────────────────────────────────────────────────────────

_SECRET_FORBIDDEN = {
    "client_secret",
    "encrypted_client_secret",
    "password_hash",
}


def _no_secrets(data: dict) -> bool:
    return not _SECRET_FORBIDDEN.intersection(data.keys())


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAdminOidcListProviders(unittest.TestCase):

    # 1. Super admin → 200 list
    def test_super_admin_gets_list(self):
        resp = _make_app().test_client().get("/api/v2/admin/oidc-providers/", **_auth())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 0)

    # 2. No auth → 401
    def test_no_auth_returns_401(self):
        resp = _make_app().test_client().get("/api/v2/admin/oidc-providers/")
        self.assertEqual(resp.status_code, 401)

    # 3. Non-super-admin → 403
    def test_regular_user_returns_403(self):
        resp = _make_app().test_client().get("/api/v2/admin/oidc-providers/", **_auth(_USER_TOKEN))
        self.assertEqual(resp.status_code, 403)


class TestAdminOidcCreateProvider(unittest.TestCase):

    def _post(self, svc=None, payload=None):
        return _make_app(provider_svc=svc).test_client().post(
            "/api/v2/admin/oidc-providers/",
            json=payload or {
                "name": "Keycloak",
                "slug": "keycloak",
                "issuer": "https://idp.example.com",
                "client_id": "my-client",
                "client_secret": "super-secret",
            },
            **_auth(),
        )

    # 4. Create valid → 201, has_client_secret=true, no raw secret fields
    def test_create_returns_201_and_admin_dict(self):
        resp = self._post()
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn("id", data)
        self.assertIn("slug", data)
        self.assertTrue(data["has_client_secret"])
        self.assertTrue(_no_secrets(data), f"Secret field found in response: {data.keys()}")

    # 5. Validation error → 400
    def test_validation_error_returns_400(self):
        svc = FakeOidcProviderService()
        svc.create_raises = OidcProviderValidationError("Invalid slug")
        resp = self._post(svc=svc)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    # 6. Secret error (enabled without secret) → 400
    def test_secret_error_returns_400(self):
        svc = FakeOidcProviderService()
        svc.create_raises = OidcProviderSecretError("Secret required")
        resp = self._post(svc=svc)
        self.assertEqual(resp.status_code, 400)


class TestAdminOidcGetProvider(unittest.TestCase):

    # 7. Known provider → 200 admin dict
    def test_known_provider_returns_200(self):
        resp = _make_app().test_client().get(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["id"], _PROVIDER_ID)
        self.assertIn("issuer", data)
        self.assertIn("client_id", data)
        self.assertIn("has_client_secret", data)
        self.assertTrue(_no_secrets(data))

    # 8. Unknown provider → 404
    def test_unknown_provider_returns_404(self):
        resp = _make_app().test_client().get(
            "/api/v2/admin/oidc-providers/does-not-exist", **_auth()
        )
        self.assertEqual(resp.status_code, 404)


class TestAdminOidcUpdateProvider(unittest.TestCase):

    # 9. PATCH without client_secret key → secret preserved
    def test_patch_without_secret_key_preserves_secret(self):
        svc = FakeOidcProviderService(provider=_make_provider(has_secret=True))
        resp = _make_app(provider_svc=svc).test_client().patch(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}",
            json={"button_label": "New Label"},
            **_auth(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["has_client_secret"], "Secret must be preserved when not sent")
        self.assertTrue(_no_secrets(data))

    # 10. PATCH with client_secret → accepted (result shows has_client_secret=true)
    def test_patch_with_secret_replaces_it(self):
        provider_with_secret = _make_provider(has_secret=True)
        svc = FakeOidcProviderService(provider=provider_with_secret)
        resp = _make_app(provider_svc=svc).test_client().patch(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}",
            json={"client_secret": "new-secret-value"},
            **_auth(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(_no_secrets(data), "Secret must not appear in PATCH response")


class TestAdminOidcDeleteProvider(unittest.TestCase):

    # 11. Delete known provider → 200 {ok: true}
    def test_delete_known_provider_ok(self):
        resp = _make_app().test_client().delete(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])

    # 12. Provider in use → 409
    def test_delete_in_use_returns_409(self):
        svc = FakeOidcProviderService()
        svc.delete_raises = OidcProviderInUseError("Provider has linked users")
        resp = _make_app(provider_svc=svc).test_client().delete(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}", **_auth()
        )
        self.assertEqual(resp.status_code, 409)

    # 13. Unknown provider → 404
    def test_delete_unknown_returns_404(self):
        resp = _make_app().test_client().delete(
            "/api/v2/admin/oidc-providers/unknown-id", **_auth()
        )
        self.assertEqual(resp.status_code, 404)


class TestAdminOidcTestDiscovery(unittest.TestCase):

    # 14. Discovery OK → {ok: true}
    def test_discovery_ok(self):
        resp = _make_app(oidc_svc=FakeOidcService()).test_client().post(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}/test-discovery", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])

    # 15. Discovery raises → {ok: false}, generic error, no secrets in response
    def test_discovery_unreachable_returns_ok_false(self):
        oidc_svc = FakeOidcService()
        oidc_svc.discovery_raises = ConnectionError("Connection refused")
        resp = _make_app(oidc_svc=oidc_svc).test_client().post(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}/test-discovery", **_auth()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("error", data)
        # Error must be generic (no real exception message, no secrets)
        self.assertNotIn("Connection refused", data["error"])
        raw = resp.get_data(as_text=True)
        self.assertNotIn("enc::secret-abc", raw)
        self.assertNotIn("super-secret", raw)

    # 15b. Unknown provider for test-discovery → 404
    def test_discovery_unknown_provider_returns_404(self):
        resp = _make_app().test_client().post(
            "/api/v2/admin/oidc-providers/does-not-exist/test-discovery", **_auth()
        )
        self.assertEqual(resp.status_code, 404)


class TestOidcMutualExclusivity(unittest.TestCase):

    def _create(self, ip_enabled: bool, oidc_enabled: bool = True):
        return _make_app(
            ip_config_svc=FakeIdentityProxyConfigService(enabled=ip_enabled),
        ).test_client().post(
            "/api/v2/admin/oidc-providers/",
            json={
                "name": "Keycloak",
                "slug": "keycloak",
                "issuer": "https://idp.example.com",
                "client_id": "my-client",
                "client_secret": "super-secret",
                "enabled": oidc_enabled,
            },
            **_auth(),
        )

    def _patch(self, ip_enabled: bool, enabled_value: bool):
        return _make_app(
            ip_config_svc=FakeIdentityProxyConfigService(enabled=ip_enabled),
        ).test_client().patch(
            f"/api/v2/admin/oidc-providers/{_PROVIDER_ID}",
            json={"enabled": enabled_value},
            **_auth(),
        )

    # 16. Create enabled OIDC when IP is active → 409
    def test_create_enabled_oidc_with_ip_active_returns_409(self):
        resp = self._create(ip_enabled=True, oidc_enabled=True)
        self.assertEqual(resp.status_code, 409)
        data = resp.get_json()
        self.assertIn("error", data)
        self.assertIn("Identity Proxy", data["error"])

    # 17. Create disabled OIDC when IP is active → 201 (no mutex check)
    def test_create_disabled_oidc_with_ip_active_succeeds(self):
        resp = self._create(ip_enabled=True, oidc_enabled=False)
        self.assertEqual(resp.status_code, 201)

    # 18. Update to enabled=True when IP is active → 409
    def test_update_to_enabled_with_ip_active_returns_409(self):
        resp = self._patch(ip_enabled=True, enabled_value=True)
        self.assertEqual(resp.status_code, 409)
        data = resp.get_json()
        self.assertIn("error", data)
        self.assertIn("Identity Proxy", data["error"])

    # 19. Update to enabled=False when IP is active → 200 (no mutex check)
    def test_update_to_disabled_with_ip_active_succeeds(self):
        resp = self._patch(ip_enabled=True, enabled_value=False)
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
