#!/usr/bin/env python3
"""
Unit tests: ApiTokenRepository.get_by_id() (SQLite).

Covers:
  1. get_by_id returns an active token by its DB id
  2. get_by_id returns None for a deactivated token

Run from project root:
    python3 scripts/tests/unit/test_oidc_api_token_get_by_id.py
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
from backend.repositories.sqlite.user_repository import UserRepository
from backend.repositories.sqlite.api_token_repository import ApiTokenRepository
from backend.models.user import User
from backend.models.api_token import ApiToken
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


def _make_token(user_id: str) -> ApiToken:
    ts = utc_now_iso()
    return ApiToken(
        id=str(uuid.uuid4()),
        user_id=user_id,
        token="l2n_" + secrets.token_urlsafe(32),
        label="oidc login token",
        is_active=True,
        created_at=ts,
        updated_at=ts,
    )


class TestApiTokenGetById(unittest.TestCase):

    def setUp(self):
        self.db, self._db_path = _make_db()
        self.user_repo = UserRepository(self.db)
        self.token_repo = ApiTokenRepository(self.db)
        self.user = _make_user(str(uuid.uuid4()), "carol@example.com")
        self.user_repo.create(self.user)

    def tearDown(self):
        os.unlink(self._db_path)

    # ── Test 1: active token found by id ─────────────────────────────────────

    def test_get_by_id_returns_active_token(self):
        token = _make_token(self.user.id)
        self.token_repo.create(token)

        found = self.token_repo.get_by_id(token.id)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, token.id)
        self.assertEqual(found.user_id, self.user.id)
        self.assertTrue(found.is_active)

    # ── Test 2: deactivated token not returned ────────────────────────────────

    def test_get_by_id_returns_none_for_deactivated_token(self):
        token = _make_token(self.user.id)
        self.token_repo.create(token)

        self.token_repo.deactivate(self.user.id, token.id)

        found = self.token_repo.get_by_id(token.id)
        self.assertIsNone(found, "Deactivated token must not be returned by get_by_id")

    def test_get_by_id_returns_none_for_unknown_id(self):
        found = self.token_repo.get_by_id(str(uuid.uuid4()))
        self.assertIsNone(found)


if __name__ == "__main__":
    unittest.main(verbosity=2)
