#!/usr/bin/env python3
"""
Unit tests: OidcProviderService.

Covers:
  1.  create_provider happy path — OidcProvider created, secret encrypted
  2.  create_provider enabled=True with no secret → OidcProviderSecretError
  3.  create_provider enabled=False with no secret → succeeds
  4.  create_provider invalid slug → OidcProviderValidationError
  5.  create_provider empty name → OidcProviderValidationError
  6.  create_provider empty client_id → OidcProviderValidationError
  7.  to_admin_dict has_client_secret=True when secret set
  8.  to_admin_dict has_client_secret=False when no secret
  9.  to_admin_dict excludes encrypted_client_secret and client_secret fields
  10. to_public_dict contains only slug and button_label
  11. list_public_enabled_providers returns [] in single_user_mode
  12. list_public_enabled_providers returns enabled providers
  13. delete_provider raises OidcProviderInUseError when count_by_issuer > 0
  14. delete_provider succeeds when count_by_issuer == 0
  15. update_provider without client_secret preserves existing encrypted_secret
  16. update_provider with new client_secret replaces encrypted_secret
  17. update_provider with client_secret=None clears encrypted_secret
  18. get_provider_or_raise raises OidcProviderNotFoundError for unknown id
  19. issuer normalization strips trailing slash

Run from project root:
    python3 scripts/tests/unit/test_oidc_provider_service.py
"""

import os
import sys
import unittest
import uuid

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.oidc_provider import OidcProvider
from backend.services_v2.oidc_provider_service import (
    OidcProviderInUseError,
    OidcProviderNotFoundError,
    OidcProviderSecretError,
    OidcProviderService,
    OidcProviderValidationError,
)
from backend.utils.time import utc_now_iso


# ── Fakes ─────────────────────────────────────────────────────────────────────


class FakeOidcProviderRepo:
    def __init__(self):
        self._by_id: dict = {}
        self._by_slug: dict = {}
        self._by_issuer: dict = {}

    def create(self, p: OidcProvider) -> None:
        self._by_id[p.id] = p
        self._by_slug[p.slug] = p
        self._by_issuer[p.issuer] = p

    def get_by_id(self, pid: str) -> OidcProvider | None:
        return self._by_id.get(pid)

    def get_by_slug(self, slug: str) -> OidcProvider | None:
        return self._by_slug.get(slug)

    def list_all(self) -> list[OidcProvider]:
        return list(self._by_id.values())

    def list_enabled(self) -> list[OidcProvider]:
        return [p for p in self._by_id.values() if p.enabled]

    def update(self, p: OidcProvider) -> None:
        self._by_id[p.id] = p

    def delete(self, pid: str) -> None:
        p = self._by_id.pop(pid, None)
        if p:
            self._by_slug.pop(p.slug, None)
            self._by_issuer.pop(p.issuer, None)


class FakeExtIdRepo:
    def __init__(self, counts: dict | None = None):
        self._counts = counts or {}

    def count_by_issuer(self, issuer: str) -> int:
        return self._counts.get(issuer, 0)


class FakeCrypto:
    def encrypt(self, value: str | None) -> str | None:
        return f"enc::{value}" if value else None

    def decrypt(self, value: str | None) -> str | None:
        if value and value.startswith("enc::"):
            return value[5:]
        return value


# ── Helpers ───────────────────────────────────────────────────────────────────


def _svc(ext_id_repo=None):
    return OidcProviderService(
        repo=FakeOidcProviderRepo(),
        ext_id_repo=ext_id_repo or FakeExtIdRepo(),
        crypto_service=FakeCrypto(),
    )


def _svc_with_repo(repo, ext_id_repo=None):
    return OidcProviderService(
        repo=repo,
        ext_id_repo=ext_id_repo or FakeExtIdRepo(),
        crypto_service=FakeCrypto(),
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestCreateProvider(unittest.TestCase):

    # 1. Happy path
    def test_create_happy_path(self):
        svc = _svc()
        p = svc.create_provider(
            name="Keycloak",
            slug="keycloak",
            issuer="https://kc.example.com/realms/test",
            client_id="link2nas",
            client_secret="super-secret",
        )
        self.assertEqual(p.slug, "keycloak")
        self.assertEqual(p.name, "Keycloak")
        self.assertTrue(p.enabled)
        # FakeCrypto.encrypt prepends "enc::" — confirms encrypt() was called
        self.assertTrue(p.encrypted_client_secret.startswith("enc::"))
        self.assertNotEqual(p.encrypted_client_secret, "super-secret")

    # 2. Enabled + no secret → error
    def test_create_enabled_no_secret_raises(self):
        svc = _svc()
        with self.assertRaises(OidcProviderSecretError):
            svc.create_provider(
                name="Test", slug="test",
                issuer="https://test.example.com",
                client_id="client", client_secret=None, enabled=True,
            )

    # 3. Disabled + no secret → ok
    def test_create_disabled_no_secret_succeeds(self):
        svc = _svc()
        p = svc.create_provider(
            name="Test", slug="test",
            issuer="https://test.example.com",
            client_id="client", client_secret=None, enabled=False,
        )
        self.assertFalse(p.enabled)
        self.assertIsNone(p.encrypted_client_secret)

    # 4. Invalid slug
    def test_create_invalid_slug_raises(self):
        svc = _svc()
        with self.assertRaises(OidcProviderValidationError):
            svc.create_provider(
                name="Test", slug="INVALID SLUG!",
                issuer="https://test.example.com",
                client_id="client", client_secret="secret",
            )

    # 5. Empty name
    def test_create_empty_name_raises(self):
        svc = _svc()
        with self.assertRaises(OidcProviderValidationError):
            svc.create_provider(
                name="  ", slug="test",
                issuer="https://test.example.com",
                client_id="client", client_secret="secret",
            )

    # 6. Empty client_id
    def test_create_empty_client_id_raises(self):
        svc = _svc()
        with self.assertRaises(OidcProviderValidationError):
            svc.create_provider(
                name="Test", slug="test",
                issuer="https://test.example.com",
                client_id="  ", client_secret="secret",
            )


class TestAdminDict(unittest.TestCase):

    def _provider(self, with_secret=True) -> OidcProvider:
        now = utc_now_iso()
        return OidcProvider(
            id=str(uuid.uuid4()), name="Test", slug="test", enabled=True,
            issuer="https://test.example.com", client_id="client",
            encrypted_client_secret="enc::abc" if with_secret else None,
            scopes="openid email profile", button_label="Sign in",
            auto_create_users=False, allowed_domains_json="[]",
            state_ttl_seconds=600, exchange_code_ttl_seconds=60,
            sort_order=0, created_at=now, updated_at=now,
        )

    # 7. has_client_secret=True when secret set
    def test_has_client_secret_true(self):
        svc = _svc()
        d = svc.to_admin_dict(self._provider(with_secret=True))
        self.assertTrue(d["has_client_secret"])

    # 8. has_client_secret=False when no secret
    def test_has_client_secret_false(self):
        svc = _svc()
        d = svc.to_admin_dict(self._provider(with_secret=False))
        self.assertFalse(d["has_client_secret"])

    # 9. Neither client_secret nor encrypted_client_secret in dict
    def test_no_secret_fields_exposed(self):
        svc = _svc()
        d = svc.to_admin_dict(self._provider(with_secret=True))
        self.assertNotIn("client_secret", d)
        self.assertNotIn("encrypted_client_secret", d)


class TestPublicDict(unittest.TestCase):

    # 10. Only slug and button_label
    def test_public_dict_only_slug_and_label(self):
        now = utc_now_iso()
        p = OidcProvider(
            id=str(uuid.uuid4()), name="Test", slug="keycloak", enabled=True,
            issuer="https://kc.example.com", client_id="client",
            encrypted_client_secret=None,
            scopes="openid email profile", button_label="Sign in with Keycloak",
            auto_create_users=False, allowed_domains_json="[]",
            state_ttl_seconds=600, exchange_code_ttl_seconds=60,
            sort_order=0, created_at=now, updated_at=now,
        )
        svc = _svc()
        d = svc.to_public_dict(p)
        self.assertEqual(set(d.keys()), {"slug", "button_label"})
        self.assertEqual(d["slug"], "keycloak")
        self.assertEqual(d["button_label"], "Sign in with Keycloak")


class TestListPublicEnabled(unittest.TestCase):

    # 11. Single-user mode → empty list
    def test_single_user_mode_returns_empty(self):
        svc = _svc()
        svc.create_provider(
            name="Keycloak", slug="keycloak",
            issuer="https://kc.example.com",
            client_id="client", client_secret="secret",
        )
        result = svc.list_public_enabled_providers(single_user_mode=True)
        self.assertEqual(result, [])

    # 12. Returns enabled providers
    def test_returns_enabled_providers(self):
        svc = _svc()
        svc.create_provider(
            name="Keycloak", slug="keycloak",
            issuer="https://kc.example.com",
            client_id="client", client_secret="secret",
        )
        svc.create_provider(
            name="Disabled", slug="disabled",
            issuer="https://disabled.example.com",
            client_id="client2", client_secret=None, enabled=False,
        )
        result = svc.list_public_enabled_providers(single_user_mode=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["slug"], "keycloak")
        self.assertIn("button_label", result[0])


class TestDeleteProvider(unittest.TestCase):

    # 13. In-use → error
    def test_delete_in_use_raises(self):
        issuer = "https://kc.example.com"
        ext_repo = FakeExtIdRepo(counts={issuer: 3})
        svc = _svc(ext_id_repo=ext_repo)
        p = svc.create_provider(
            name="Keycloak", slug="keycloak",
            issuer=issuer,
            client_id="client", client_secret="secret",
        )
        with self.assertRaises(OidcProviderInUseError):
            svc.delete_provider(p.id)

    # 14. Not in use → succeeds
    def test_delete_not_in_use_succeeds(self):
        svc = _svc()
        p = svc.create_provider(
            name="Keycloak", slug="keycloak",
            issuer="https://kc.example.com",
            client_id="client", client_secret="secret",
        )
        svc.delete_provider(p.id)
        with self.assertRaises(OidcProviderNotFoundError):
            svc.get_provider_or_raise(p.id)


class TestUpdateProvider(unittest.TestCase):

    def _create(self, svc) -> OidcProvider:
        return svc.create_provider(
            name="Keycloak", slug="keycloak",
            issuer="https://kc.example.com",
            client_id="client", client_secret="original-secret",
        )

    # 15. No client_secret → preserves existing encrypted_secret
    def test_update_no_secret_preserves_existing(self):
        svc = _svc()
        p = self._create(svc)
        original_enc = p.encrypted_client_secret

        updated = svc.update_provider(p.id, name="Keycloak Renamed")

        self.assertEqual(updated.encrypted_client_secret, original_enc)
        self.assertEqual(updated.name, "Keycloak Renamed")

    # 16. New client_secret → replaces
    def test_update_new_secret_replaces(self):
        svc = _svc()
        p = self._create(svc)
        original_enc = p.encrypted_client_secret

        updated = svc.update_provider(p.id, client_secret="new-secret")

        self.assertNotEqual(updated.encrypted_client_secret, original_enc)
        self.assertIn("new-secret", updated.encrypted_client_secret)

    # 17. client_secret=None → clears
    def test_update_secret_none_clears(self):
        svc = _svc()
        p = self._create(svc)

        updated = svc.update_provider(p.id, client_secret=None)

        self.assertIsNone(updated.encrypted_client_secret)


class TestGetProviderOrRaise(unittest.TestCase):

    # 18. Unknown id → OidcProviderNotFoundError
    def test_get_unknown_raises(self):
        svc = _svc()
        with self.assertRaises(OidcProviderNotFoundError):
            svc.get_provider_or_raise("no-such-id")


class TestIssuerNormalization(unittest.TestCase):

    # 19. Trailing slash stripped
    def test_trailing_slash_stripped(self):
        svc = _svc()
        p = svc.create_provider(
            name="Test", slug="test",
            issuer="https://test.example.com/realms/demo/",
            client_id="client", client_secret="secret",
        )
        self.assertEqual(p.issuer, "https://test.example.com/realms/demo")


if __name__ == "__main__":
    unittest.main(verbosity=2)
