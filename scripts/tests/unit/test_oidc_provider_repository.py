#!/usr/bin/env python3
"""
Unit tests: OidcProviderRepository (SQLite).

Covers:
  1.  create + get_by_id
  2.  get_by_id returns None for unknown
  3.  get_by_slug
  4.  get_by_slug returns None for unknown
  5.  get_by_issuer
  6.  get_by_issuer returns None for unknown
  7.  list_all ordered by sort_order then created_at
  8.  list_enabled excludes disabled providers
  9.  list_enabled returns empty when none are enabled
  10. update — all mutable fields
  11. update — encrypted_client_secret replaced when set to new value
  12. update — encrypted_client_secret cleared when set to None
  13. delete removes the row
  14. UNIQUE slug constraint raises on duplicate
  15. UNIQUE issuer constraint raises on duplicate
  16. encrypted_client_secret stored and retrieved as-is (not transformed)

Run from project root:
    python3 scripts/tests/unit/test_oidc_provider_repository.py
"""

import os
import sys
import tempfile
import unittest
import uuid

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.storage.db import Database
from backend.repositories.sqlite.oidc_provider_repository import OidcProviderRepository
from backend.models.oidc_provider import OidcProvider
from backend.utils.time import utc_now_iso


def _make_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = Database(tmp.name)
    db.init_schema(os.path.join(_PROJECT_ROOT, "backend", "storage", "schema.sql"))
    db.run_column_migrations()
    return db, tmp.name


def _make_provider(
    *,
    slug: str = "keycloak",
    issuer: str = "https://keycloak.example.com/realms/test",
    name: str = "Keycloak",
    enabled: bool = True,
    sort_order: int = 0,
    encrypted_client_secret: str | None = "enc:abc123",
    created_at: str | None = None,
) -> OidcProvider:
    now = created_at or utc_now_iso()
    return OidcProvider(
        id=str(uuid.uuid4()),
        name=name,
        slug=slug,
        enabled=enabled,
        issuer=issuer,
        client_id="link2nas-client",
        encrypted_client_secret=encrypted_client_secret,
        scopes="openid email profile",
        button_label=f"Sign in with {name}",
        auto_create_users=False,
        allowed_domains_json="[]",
        state_ttl_seconds=600,
        exchange_code_ttl_seconds=60,
        sort_order=sort_order,
        created_at=now,
        updated_at=now,
    )


class TestOidcProviderRepository(unittest.TestCase):

    def setUp(self):
        self.db, self._db_path = _make_db()
        self.repo = OidcProviderRepository(self.db)

    def tearDown(self):
        os.unlink(self._db_path)

    # ── 1. create + get_by_id ─────────────────────────────────────────────────

    def test_create_and_get_by_id(self):
        p = _make_provider()
        self.repo.create(p)

        found = self.repo.get_by_id(p.id)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, p.id)
        self.assertEqual(found.slug, "keycloak")
        self.assertEqual(found.issuer, p.issuer)
        self.assertEqual(found.client_id, "link2nas-client")
        self.assertTrue(found.enabled)
        self.assertFalse(found.auto_create_users)
        self.assertEqual(found.allowed_domains_json, "[]")
        self.assertEqual(found.state_ttl_seconds, 600)
        self.assertEqual(found.exchange_code_ttl_seconds, 60)

    # ── 2. get_by_id returns None for unknown ─────────────────────────────────

    def test_get_by_id_returns_none_for_unknown(self):
        self.assertIsNone(self.repo.get_by_id("no-such-id"))

    # ── 3. get_by_slug ────────────────────────────────────────────────────────

    def test_get_by_slug(self):
        p = _make_provider(slug="google", issuer="https://accounts.google.com")
        self.repo.create(p)

        found = self.repo.get_by_slug("google")
        self.assertIsNotNone(found)
        self.assertEqual(found.id, p.id)

    # ── 4. get_by_slug returns None for unknown ───────────────────────────────

    def test_get_by_slug_returns_none_for_unknown(self):
        self.assertIsNone(self.repo.get_by_slug("unknown-slug"))

    # ── 5. get_by_issuer ──────────────────────────────────────────────────────

    def test_get_by_issuer(self):
        p = _make_provider(issuer="https://auth.example.com")
        self.repo.create(p)

        found = self.repo.get_by_issuer("https://auth.example.com")
        self.assertIsNotNone(found)
        self.assertEqual(found.id, p.id)

    # ── 6. get_by_issuer returns None for unknown ─────────────────────────────

    def test_get_by_issuer_returns_none_for_unknown(self):
        self.assertIsNone(self.repo.get_by_issuer("https://unknown.example.com"))

    # ── 7. list_all ordered by sort_order then created_at ────────────────────

    def test_list_all_ordered_by_sort_order_then_created_at(self):
        import time
        p_b = _make_provider(slug="b", issuer="https://b.example.com", sort_order=2)
        self.repo.create(p_b)
        time.sleep(0.01)
        p_a1 = _make_provider(slug="a1", issuer="https://a1.example.com", sort_order=1)
        self.repo.create(p_a1)
        time.sleep(0.01)
        p_a2 = _make_provider(slug="a2", issuer="https://a2.example.com", sort_order=1)
        self.repo.create(p_a2)

        results = self.repo.list_all()
        self.assertEqual(len(results), 3)
        slugs = [r.slug for r in results]
        # sort_order=1 before sort_order=2; within sort_order=1, a1 before a2 by created_at
        self.assertEqual(slugs, ["a1", "a2", "b"])

    # ── 8. list_enabled excludes disabled ─────────────────────────────────────

    def test_list_enabled_excludes_disabled(self):
        p_on = _make_provider(slug="enabled-one", issuer="https://on.example.com", enabled=True)
        p_off = _make_provider(slug="disabled-one", issuer="https://off.example.com", enabled=False)
        self.repo.create(p_on)
        self.repo.create(p_off)

        results = self.repo.list_enabled()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].slug, "enabled-one")

    # ── 9. list_enabled returns empty when none are enabled ───────────────────

    def test_list_enabled_returns_empty_when_none_enabled(self):
        p = _make_provider(enabled=False)
        self.repo.create(p)
        self.assertEqual(self.repo.list_enabled(), [])

    # ── 10. update — all mutable fields ──────────────────────────────────────

    def test_update_fields(self):
        p = _make_provider()
        self.repo.create(p)

        p.name = "Keycloak Updated"
        p.button_label = "Sign in with Keycloak (prod)"
        p.enabled = False
        p.auto_create_users = True
        p.allowed_domains_json = '["example.com"]'
        p.sort_order = 5
        p.updated_at = utc_now_iso()
        self.repo.update(p)

        found = self.repo.get_by_id(p.id)
        self.assertEqual(found.name, "Keycloak Updated")
        self.assertEqual(found.button_label, "Sign in with Keycloak (prod)")
        self.assertFalse(found.enabled)
        self.assertTrue(found.auto_create_users)
        self.assertEqual(found.allowed_domains_json, '["example.com"]')
        self.assertEqual(found.sort_order, 5)

    # ── 11. update — encrypted_client_secret replaced when new value set ─────

    def test_update_replaces_encrypted_secret(self):
        p = _make_provider(encrypted_client_secret="enc:old-secret")
        self.repo.create(p)

        p.encrypted_client_secret = "enc:new-secret"
        p.updated_at = utc_now_iso()
        self.repo.update(p)

        found = self.repo.get_by_id(p.id)
        self.assertEqual(found.encrypted_client_secret, "enc:new-secret")

    # ── 12. update — encrypted_client_secret cleared when set to None ────────

    def test_update_clears_encrypted_secret_when_none(self):
        p = _make_provider(encrypted_client_secret="enc:some-secret")
        self.repo.create(p)

        p.encrypted_client_secret = None
        p.updated_at = utc_now_iso()
        self.repo.update(p)

        found = self.repo.get_by_id(p.id)
        self.assertIsNone(found.encrypted_client_secret)

    # ── 13. delete removes the row ────────────────────────────────────────────

    def test_delete_removes_row(self):
        p = _make_provider()
        self.repo.create(p)
        self.assertIsNotNone(self.repo.get_by_id(p.id))

        self.repo.delete(p.id)
        self.assertIsNone(self.repo.get_by_id(p.id))

    # ── 14. UNIQUE slug constraint ────────────────────────────────────────────

    def test_duplicate_slug_raises(self):
        p1 = _make_provider(slug="same-slug", issuer="https://issuer-a.example.com")
        p2 = _make_provider(slug="same-slug", issuer="https://issuer-b.example.com")
        self.repo.create(p1)
        with self.assertRaises(Exception):
            self.repo.create(p2)

    # ── 15. UNIQUE issuer constraint ──────────────────────────────────────────

    def test_duplicate_issuer_raises(self):
        p1 = _make_provider(slug="slug-a", issuer="https://shared-issuer.example.com")
        p2 = _make_provider(slug="slug-b", issuer="https://shared-issuer.example.com")
        self.repo.create(p1)
        with self.assertRaises(Exception):
            self.repo.create(p2)

    # ── 16. encrypted_client_secret stored and retrieved as-is ───────────────

    def test_encrypted_secret_stored_as_is(self):
        encrypted_value = "gAAAAABfake-fernet-token-for-test-purposes-only=="
        p = _make_provider(encrypted_client_secret=encrypted_value)
        self.repo.create(p)

        found = self.repo.get_by_id(p.id)
        self.assertEqual(found.encrypted_client_secret, encrypted_value,
                         "Repository must store and return encrypted_client_secret unchanged")


if __name__ == "__main__":
    unittest.main(verbosity=2)
