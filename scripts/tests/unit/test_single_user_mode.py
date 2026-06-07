#!/usr/bin/env python3
"""
Unit tests: single-user mode — service and setup/status behaviour.

Covers:
  1. single-user + fresh DB: get_or_create_single_user() creates the user and
     returns it without error. (Simulates setup_required=False in single-user mode.)
  2. multi-user + fresh DB: count_users()==0 → setup_required True.
  3. multi-user + existing user: count_users()>0 → setup_required False.
  4. single-user + existing user with same email: get_or_create_single_user()
     reuses the existing account (no RuntimeError raised).
  5. single-user + existing canonical user (SINGLE_USER_ID): returns that user.
  6. get_or_create_single_user() promotes role to super_admin if needed.
  7. get_or_create_single_user() sets is_active=True if the reused user was disabled.

Run from project root:
    python scripts/tests/unit/test_single_user_mode.py
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
from backend.services_v2.single_user_service import SingleUserService, SINGLE_USER_ID
from backend.models.user import User
from backend.utils.time import utc_now_iso


def _make_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = Database(tmp.name)
    schema = os.path.join(_PROJECT_ROOT, "backend", "storage", "schema.sql")
    db.init_schema(schema)
    db.run_column_migrations()
    return db, tmp.name


def _make_settings(email="admin@example.com", display_name="Admin", single=True):
    class FakeSettings:
        LINK2NAS_SINGLE_USER_MODE = single
        LINK2NAS_SINGLE_USER_EMAIL = email
        LINK2NAS_SINGLE_USER_DISPLAY_NAME = display_name
    return FakeSettings()


def _make_user(user_id: str, email: str, role: str = "user", is_active: bool = True) -> User:
    ts = utc_now_iso()
    return User(
        id=user_id,
        email=email,
        display_name="Test",
        role=role,
        is_active=is_active,
        created_at=ts,
        updated_at=ts,
        password_hash="hashed",
    )


class TestSingleUserService(unittest.TestCase):

    def setUp(self):
        self.db, self.db_path = _make_db()
        self.user_repo = UserRepository(self.db)

    def tearDown(self):
        os.unlink(self.db_path)

    # ── Test 1: fresh DB, single-user mode → creates user ─────────────────────

    def test_fresh_db_creates_single_user(self):
        settings = _make_settings(email="solo@example.com")
        svc = SingleUserService(self.user_repo, settings)

        user = svc.get_or_create_single_user()

        self.assertIsNotNone(user)
        self.assertEqual(user.id, SINGLE_USER_ID)
        self.assertEqual(user.email, "solo@example.com")
        self.assertEqual(user.role, "super_admin")
        self.assertTrue(user.is_active)

    # ── Test 2: multi-user, fresh DB → count_users() == 0 ─────────────────────

    def test_multi_user_fresh_db_count_zero(self):
        self.assertEqual(self.user_repo.count_users(), 0)

    # ── Test 3: multi-user, user exists → count_users() > 0 ───────────────────

    def test_multi_user_existing_user_count_nonzero(self):
        self.user_repo.create(_make_user(str(uuid.uuid4()), "user@example.com"))
        self.assertGreater(self.user_repo.count_users(), 0)

    # ── Test 4: single-user + existing user with same email → reuses it ───────

    def test_existing_email_user_is_reused(self):
        existing_id = str(uuid.uuid4())
        self.user_repo.create(_make_user(existing_id, "admin@example.com", role="user"))

        settings = _make_settings(email="admin@example.com")
        svc = SingleUserService(self.user_repo, settings)

        # Must NOT raise — must reuse the existing user
        user = svc.get_or_create_single_user()

        self.assertEqual(user.id, existing_id, "Must return the existing user by email")
        self.assertEqual(user.role, "super_admin", "Must have been promoted to super_admin")
        self.assertTrue(user.is_active)

    # ── Test 5: canonical single-user (SINGLE_USER_ID) takes priority ─────────

    def test_canonical_id_takes_priority(self):
        # Insert canonical single-user
        self.user_repo.create(_make_user(SINGLE_USER_ID, "canonical@example.com", role="user"))
        # Also insert another user with the configured email
        self.user_repo.create(_make_user(str(uuid.uuid4()), "configured@example.com", role="user"))

        settings = _make_settings(email="configured@example.com")
        svc = SingleUserService(self.user_repo, settings)

        user = svc.get_or_create_single_user()

        self.assertEqual(user.id, SINGLE_USER_ID, "Canonical ID must take priority over email match")

    # ── Test 6: role is promoted to super_admin ────────────────────────────────

    def test_role_promoted_to_super_admin(self):
        self.user_repo.create(_make_user(SINGLE_USER_ID, "x@example.com", role="user"))

        settings = _make_settings(email="x@example.com")
        svc = SingleUserService(self.user_repo, settings)

        user = svc.get_or_create_single_user()
        self.assertEqual(user.role, "super_admin")

        # Verify it was persisted
        from_db = self.user_repo.get_by_id(SINGLE_USER_ID)
        self.assertEqual(from_db.role, "super_admin")

    # ── Test 7: disabled user re-activated ────────────────────────────────────

    def test_disabled_user_is_reactivated(self):
        disabled = _make_user(SINGLE_USER_ID, "x@example.com", is_active=False)
        self.user_repo.create(disabled)

        settings = _make_settings(email="x@example.com")
        svc = SingleUserService(self.user_repo, settings)

        user = svc.get_or_create_single_user()
        self.assertTrue(user.is_active)

        from_db = self.user_repo.get_by_id(SINGLE_USER_ID)
        self.assertTrue(from_db.is_active)

    # ── Test 8: second call returns same user (idempotent) ────────────────────

    def test_idempotent(self):
        settings = _make_settings(email="solo@example.com")
        svc = SingleUserService(self.user_repo, settings)

        user_a = svc.get_or_create_single_user()
        user_b = svc.get_or_create_single_user()

        self.assertEqual(user_a.id, user_b.id)
        self.assertEqual(self.user_repo.count_users(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
