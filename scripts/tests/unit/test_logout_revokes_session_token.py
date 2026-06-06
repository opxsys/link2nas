#!/usr/bin/env python3
"""
Unit test: logout deactivates the session token server-side.

Covers:
  - An active session token is found by get_active_by_token before logout.
  - After deactivate(), the same token is no longer found by get_active_by_token.
  - Calling deactivate() on an already-deactivated token does not raise.
  - A second session token for the same user is not affected.
  - User API Keys (user_api_keys table) are a separate table — not touched.

Run from project root:
    python scripts/tests/unit/test_logout_revokes_session_token.py
"""

import os
import sys
import secrets
import tempfile
import unittest
import uuid

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.storage.db import Database
from backend.repositories.sqlite.api_token_repository import ApiTokenRepository
from backend.repositories.sqlite.user_repository import UserRepository
from backend.models.api_token import ApiToken
from backend.models.user import User
from backend.utils.time import utc_now_iso


def _make_user(user_id: str, email: str) -> User:
    ts = utc_now_iso()
    return User(
        id=user_id,
        email=email,
        display_name=None,
        role="user",
        is_active=True,
        created_at=ts,
        updated_at=ts,
        password_hash="hashed",
    )


def _make_token(user_id: str, raw_token: str, label: str = "login token") -> ApiToken:
    ts = utc_now_iso()
    return ApiToken(
        id=str(uuid.uuid4()),
        user_id=user_id,
        token=raw_token,
        label=label,
        is_active=True,
        created_at=ts,
        updated_at=ts,
    )


class TestLogoutRevokesSessionToken(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        db = Database(self._tmp.name)
        schema = os.path.join(_PROJECT_ROOT, "backend", "storage", "schema.sql")
        db.init_schema(schema)
        db.run_column_migrations()

        self.token_repo = ApiTokenRepository(db)
        self.user_repo = UserRepository(db)

        self.user = _make_user("user-001", "alice@example.com")
        self.user_repo.create(self.user)

    def tearDown(self):
        os.unlink(self._tmp.name)

    def test_token_is_active_before_logout(self):
        raw = "l2n_" + secrets.token_urlsafe(32)
        token = _make_token(self.user.id, raw)
        self.token_repo.create(token)

        found = self.token_repo.get_active_by_token(raw)
        self.assertIsNotNone(found, "Token must be active before logout")

    def test_token_is_invalid_after_deactivate(self):
        raw = "l2n_" + secrets.token_urlsafe(32)
        token = _make_token(self.user.id, raw)
        self.token_repo.create(token)

        found = self.token_repo.get_active_by_token(raw)
        self.assertIsNotNone(found)

        self.token_repo.deactivate(found.user_id, found.id)

        after = self.token_repo.get_active_by_token(raw)
        self.assertIsNone(after, "Token must be invalid after deactivate (simulates logout)")

    def test_deactivate_is_idempotent(self):
        raw = "l2n_" + secrets.token_urlsafe(32)
        token = _make_token(self.user.id, raw)
        self.token_repo.create(token)

        found = self.token_repo.get_active_by_token(raw)
        self.token_repo.deactivate(found.user_id, found.id)
        # Second call must not raise
        self.token_repo.deactivate(found.user_id, found.id)
        self.assertIsNone(self.token_repo.get_active_by_token(raw))

    def test_other_token_for_same_user_is_not_revoked(self):
        raw_a = "l2n_" + secrets.token_urlsafe(32)
        raw_b = "l2n_" + secrets.token_urlsafe(32)
        token_a = _make_token(self.user.id, raw_a)
        token_b = _make_token(self.user.id, raw_b)
        self.token_repo.create(token_a)
        self.token_repo.create(token_b)

        found_a = self.token_repo.get_active_by_token(raw_a)
        self.token_repo.deactivate(found_a.user_id, found_a.id)

        self.assertIsNone(self.token_repo.get_active_by_token(raw_a))
        self.assertIsNotNone(
            self.token_repo.get_active_by_token(raw_b),
            "Second token for the same user must remain active",
        )

    def test_magic_login_token_is_also_a_session_token(self):
        raw = "l2n_" + secrets.token_urlsafe(32)
        token = _make_token(self.user.id, raw, label="magic login token")
        self.token_repo.create(token)

        found = self.token_repo.get_active_by_token(raw)
        self.assertIsNotNone(found)
        self.token_repo.deactivate(found.user_id, found.id)
        self.assertIsNone(self.token_repo.get_active_by_token(raw))

    def test_unknown_token_returns_none(self):
        result = self.token_repo.get_active_by_token("l2n_doesnotexist")
        self.assertIsNone(result, "Unknown token must return None (logout remains a no-op)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
