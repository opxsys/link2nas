#!/usr/bin/env python3
"""
Unit tests: IdentityProxyConfigRepository (SQLite).

Covers:
  1.  create + get_by_id
  2.  get_by_id returns None for unknown id
  3.  get_first returns None on empty table
  4.  get_first returns the config with the earliest created_at
  5.  get_first is deterministic when multiple rows exist
  6.  list_all returns all configs ordered by created_at asc
  7.  list_all returns empty list on empty table
  8.  update — all mutable fields
  9.  delete removes the row
  10. delete on unknown id does not raise
  11. bool conversion — enabled stored as INTEGER 0/1, read back as bool
  12. bool conversion — auto_login stored as INTEGER 0/1, read back as bool
  13. bool conversion — auto_create_users stored as INTEGER 0/1, read back as bool
  14. allowed_domains_json stored and retrieved verbatim
  15. config_json stored and retrieved verbatim

Run from project root:
    python3 scripts/tests/unit/test_identity_proxy_config_repository.py
"""

import os
import sys
import tempfile
import time
import unittest
import uuid

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.storage.db import Database
from backend.repositories.sqlite.identity_proxy_config_repository import (
    IdentityProxyConfigRepository,
)
from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.utils.time import utc_now_iso


def _make_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = Database(tmp.name)
    db.init_schema(os.path.join(_PROJECT_ROOT, "backend", "storage", "schema.sql"))
    db.run_column_migrations()
    return db, tmp.name


def _make_config(
    *,
    enabled: bool = False,
    auto_login: bool = True,
    auto_create_users: bool = False,
    allowed_domains_json: str = "[]",
    config_json: str = '{"team_domain": "leang.cloudflareaccess.com", "audience": "test-aud"}',
    created_at: str | None = None,
) -> IdentityProxyConfig:
    now = created_at or utc_now_iso()
    return IdentityProxyConfig(
        id=str(uuid.uuid4()),
        name="Cloudflare Access",
        provider_type="cloudflare_access",
        enabled=enabled,
        label="Continue with Cloudflare Access",
        auto_login=auto_login,
        auto_create_users=auto_create_users,
        allowed_domains_json=allowed_domains_json,
        config_json=config_json,
        created_at=now,
        updated_at=now,
    )


class TestIdentityProxyConfigRepository(unittest.TestCase):

    def setUp(self):
        self.db, self._db_path = _make_db()
        self.repo = IdentityProxyConfigRepository(self.db)

    def tearDown(self):
        os.unlink(self._db_path)

    # ── 1. create + get_by_id ────────────────────────────────────────────────

    def test_create_and_get_by_id(self):
        cfg = _make_config()
        self.repo.create(cfg)

        found = self.repo.get_by_id(cfg.id)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, cfg.id)
        self.assertEqual(found.name, "Cloudflare Access")
        self.assertEqual(found.provider_type, "cloudflare_access")
        self.assertEqual(found.label, "Continue with Cloudflare Access")
        self.assertEqual(found.created_at, cfg.created_at)
        self.assertEqual(found.updated_at, cfg.updated_at)

    # ── 2. get_by_id returns None for unknown ────────────────────────────────

    def test_get_by_id_returns_none_for_unknown(self):
        self.assertIsNone(self.repo.get_by_id("no-such-id"))

    # ── 3. get_first returns None on empty table ─────────────────────────────

    def test_get_first_returns_none_on_empty_table(self):
        self.assertIsNone(self.repo.get_first())

    # ── 4. get_first returns the config with earliest created_at ────────────

    def test_get_first_returns_earliest_by_created_at(self):
        cfg_first = _make_config(created_at="2026-01-01T00:00:00")
        cfg_second = _make_config(created_at="2026-06-01T00:00:00")
        self.repo.create(cfg_second)
        self.repo.create(cfg_first)

        found = self.repo.get_first()
        self.assertIsNotNone(found)
        self.assertEqual(found.id, cfg_first.id)

    # ── 5. get_first is deterministic with multiple rows ─────────────────────

    def test_get_first_deterministic(self):
        cfg_a = _make_config(created_at="2026-03-01T00:00:00")
        cfg_b = _make_config(created_at="2026-03-02T00:00:00")
        cfg_c = _make_config(created_at="2026-03-03T00:00:00")
        for cfg in (cfg_c, cfg_a, cfg_b):
            self.repo.create(cfg)

        found = self.repo.get_first()
        self.assertEqual(found.id, cfg_a.id)

    # ── 6. list_all returns all configs ordered by created_at asc ────────────

    def test_list_all_ordered_by_created_at_asc(self):
        cfg_b = _make_config(created_at="2026-06-02T00:00:00")
        cfg_a = _make_config(created_at="2026-06-01T00:00:00")
        cfg_c = _make_config(created_at="2026-06-03T00:00:00")
        for cfg in (cfg_b, cfg_c, cfg_a):
            self.repo.create(cfg)

        results = self.repo.list_all()
        self.assertEqual(len(results), 3)
        self.assertEqual([r.id for r in results], [cfg_a.id, cfg_b.id, cfg_c.id])

    # ── 7. list_all returns empty list on empty table ─────────────────────────

    def test_list_all_empty(self):
        self.assertEqual(self.repo.list_all(), [])

    # ── 8. update — all mutable fields ───────────────────────────────────────

    def test_update_all_mutable_fields(self):
        cfg = _make_config(enabled=False, auto_login=True, auto_create_users=False)
        self.repo.create(cfg)

        cfg.name = "CF Access (prod)"
        cfg.provider_type = "cloudflare_access"
        cfg.enabled = True
        cfg.label = "Sign in via Cloudflare"
        cfg.auto_login = False
        cfg.auto_create_users = True
        cfg.allowed_domains_json = '["corp.example.com"]'
        cfg.config_json = '{"team_domain": "corp.cloudflareaccess.com", "audience": "new-aud"}'
        cfg.updated_at = "2026-06-08T12:00:00"
        self.repo.update(cfg)

        found = self.repo.get_by_id(cfg.id)
        self.assertEqual(found.name, "CF Access (prod)")
        self.assertEqual(found.label, "Sign in via Cloudflare")
        self.assertTrue(found.enabled)
        self.assertFalse(found.auto_login)
        self.assertTrue(found.auto_create_users)
        self.assertEqual(found.allowed_domains_json, '["corp.example.com"]')
        self.assertEqual(found.config_json, '{"team_domain": "corp.cloudflareaccess.com", "audience": "new-aud"}')
        self.assertEqual(found.updated_at, "2026-06-08T12:00:00")

    # ── 9. delete removes the row ─────────────────────────────────────────────

    def test_delete_removes_row(self):
        cfg = _make_config()
        self.repo.create(cfg)
        self.assertIsNotNone(self.repo.get_by_id(cfg.id))

        self.repo.delete(cfg.id)
        self.assertIsNone(self.repo.get_by_id(cfg.id))
        self.assertIsNone(self.repo.get_first())

    # ── 10. delete on unknown id does not raise ───────────────────────────────

    def test_delete_unknown_id_does_not_raise(self):
        self.repo.delete("non-existent-id")  # must not raise

    # ── 11. bool — enabled stored as INTEGER, read back as bool ──────────────

    def test_bool_enabled_false(self):
        cfg = _make_config(enabled=False)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertIs(type(found.enabled), bool)
        self.assertFalse(found.enabled)

    def test_bool_enabled_true(self):
        cfg = _make_config(enabled=True)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertIs(type(found.enabled), bool)
        self.assertTrue(found.enabled)

    # ── 12. bool — auto_login stored as INTEGER, read back as bool ────────────

    def test_bool_auto_login_false(self):
        cfg = _make_config(auto_login=False)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertIs(type(found.auto_login), bool)
        self.assertFalse(found.auto_login)

    def test_bool_auto_login_true(self):
        cfg = _make_config(auto_login=True)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertIs(type(found.auto_login), bool)
        self.assertTrue(found.auto_login)

    # ── 13. bool — auto_create_users stored as INTEGER, read back as bool ────

    def test_bool_auto_create_users_false(self):
        cfg = _make_config(auto_create_users=False)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertIs(type(found.auto_create_users), bool)
        self.assertFalse(found.auto_create_users)

    def test_bool_auto_create_users_true(self):
        cfg = _make_config(auto_create_users=True)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertIs(type(found.auto_create_users), bool)
        self.assertTrue(found.auto_create_users)

    # ── 14. allowed_domains_json stored and retrieved verbatim ───────────────

    def test_allowed_domains_json_verbatim(self):
        raw = '["example.com", "corp.example.org"]'
        cfg = _make_config(allowed_domains_json=raw)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertEqual(found.allowed_domains_json, raw)

    def test_allowed_domains_json_empty_array(self):
        cfg = _make_config(allowed_domains_json="[]")
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertEqual(found.allowed_domains_json, "[]")

    # ── 15. config_json stored and retrieved verbatim ─────────────────────────

    def test_config_json_verbatim(self):
        raw = '{"team_domain": "leang.cloudflareaccess.com", "audience": "xyz-abc-123"}'
        cfg = _make_config(config_json=raw)
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertEqual(found.config_json, raw)

    def test_config_json_empty_object(self):
        cfg = _make_config(config_json="{}")
        self.repo.create(cfg)
        found = self.repo.get_by_id(cfg.id)
        self.assertEqual(found.config_json, "{}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
