#!/usr/bin/env python3
"""
Unit tests: ExternalIdentityRepository (SQLite).

Covers:
  1. create + get_by_issuer_subject
  2. get_by_user_id
  3. update_last_used
  4. UNIQUE (issuer, subject) constraint enforced

Run from project root:
    python3 scripts/tests/unit/test_oidc_external_identity_repository.py
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
from backend.repositories.sqlite.user_repository import UserRepository
from backend.repositories.sqlite.external_identity_repository import ExternalIdentityRepository
from backend.models.user import User
from backend.models.external_identity import ExternalIdentity
from backend.utils.time import utc_now_iso


def _make_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = Database(tmp.name)
    db.init_schema(os.path.join(_PROJECT_ROOT, "backend", "storage", "schema.sql"))
    db.run_column_migrations()
    return db, tmp.name


def _make_user(user_id: str, email: str) -> User:
    ts = utc_now_iso()
    return User(
        id=user_id, email=email, display_name=None,
        role="user", is_active=True, created_at=ts, updated_at=ts,
    )


def _make_identity(user_id: str, issuer: str = "https://issuer.example", subject: str = "sub-001") -> ExternalIdentity:
    ts = utc_now_iso()
    return ExternalIdentity(
        id=str(uuid.uuid4()),
        user_id=user_id,
        provider="oidc",
        issuer=issuer,
        subject=subject,
        email="user@example.com",
        linked_at=ts,
    )


class TestExternalIdentityRepository(unittest.TestCase):

    def setUp(self):
        self.db, self._db_path = _make_db()
        self.user_repo = UserRepository(self.db)
        self.ext_id_repo = ExternalIdentityRepository(self.db)
        self.user = _make_user(str(uuid.uuid4()), "alice@example.com")
        self.user_repo.create(self.user)

    def tearDown(self):
        os.unlink(self._db_path)

    # ── Test 1: create + get_by_issuer_subject ────────────────────────────────

    def test_create_and_get_by_issuer_subject(self):
        identity = _make_identity(self.user.id)
        self.ext_id_repo.create(identity)

        found = self.ext_id_repo.get_by_issuer_subject(identity.issuer, identity.subject)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, identity.id)
        self.assertEqual(found.user_id, self.user.id)
        self.assertEqual(found.provider, "oidc")
        self.assertEqual(found.email, "user@example.com")

    def test_get_by_issuer_subject_returns_none_when_absent(self):
        result = self.ext_id_repo.get_by_issuer_subject("https://unknown.issuer", "no-sub")
        self.assertIsNone(result)

    # ── Test 2: get_by_user_id ────────────────────────────────────────────────

    def test_get_by_user_id_returns_all_identities(self):
        id1 = _make_identity(self.user.id, issuer="https://issuer.a", subject="sub-a")
        id2 = _make_identity(self.user.id, issuer="https://issuer.b", subject="sub-b")
        self.ext_id_repo.create(id1)
        self.ext_id_repo.create(id2)

        results = self.ext_id_repo.get_by_user_id(self.user.id)
        self.assertEqual(len(results), 2)
        ids = {r.id for r in results}
        self.assertIn(id1.id, ids)
        self.assertIn(id2.id, ids)

    def test_get_by_user_id_returns_empty_for_unknown_user(self):
        results = self.ext_id_repo.get_by_user_id("unknown-user-id")
        self.assertEqual(results, [])

    # ── Test 3: update_last_used ──────────────────────────────────────────────

    def test_update_last_used_persists(self):
        identity = _make_identity(self.user.id)
        self.ext_id_repo.create(identity)

        new_ts = utc_now_iso()
        self.ext_id_repo.update_last_used(identity.id, new_ts)

        found = self.ext_id_repo.get_by_issuer_subject(identity.issuer, identity.subject)
        self.assertEqual(found.last_used_at, new_ts)

    # ── Test 4: UNIQUE (issuer, subject) constraint ───────────────────────────

    def test_duplicate_issuer_subject_raises(self):
        id1 = _make_identity(self.user.id, issuer="https://issuer.example", subject="sub-dup")
        self.ext_id_repo.create(id1)

        other_user = _make_user(str(uuid.uuid4()), "bob@example.com")
        self.user_repo.create(other_user)
        id2 = _make_identity(other_user.id, issuer="https://issuer.example", subject="sub-dup")

        with self.assertRaises(Exception):
            self.ext_id_repo.create(id2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
