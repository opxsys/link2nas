#!/usr/bin/env python3
"""
Unit tests: OidcStateRepository (SQLite).

Covers:
  1. create + get_valid_by_state
  2. get_valid_by_state excludes consumed states
  3. get_valid_by_state excludes expired states
  4. mark_callback_consumed sets exchange_code/api_token_id/consumed_at/expires_at
  5. get_valid_by_exchange_code requires api_token_id IS NOT NULL
  6. delete removes the row
  7. delete_expired removes only expired states

Run from project root:
    python3 scripts/tests/unit/test_oidc_state_repository.py
"""

import os
import sys
import secrets
import tempfile
import unittest
import uuid
from datetime import UTC, datetime, timedelta

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.storage.db import Database
from backend.repositories.sqlite.oidc_state_repository import OidcStateRepository
from backend.models.oidc_state import OidcState
from backend.utils.time import utc_now_iso


def _make_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = Database(tmp.name)
    db.init_schema(os.path.join(_PROJECT_ROOT, "backend", "storage", "schema.sql"))
    db.run_column_migrations()
    return db, tmp.name


def _past_iso(seconds: int = 3600) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()


def _future_iso(seconds: int = 3600) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def _make_state(state_val: str | None = None, expires_at: str | None = None) -> OidcState:
    now = utc_now_iso()
    return OidcState(
        id=str(uuid.uuid4()),
        state=state_val or ("state_" + secrets.token_urlsafe(16)),
        nonce="nonce_" + secrets.token_urlsafe(16),
        created_at=now,
        expires_at=expires_at or _future_iso(600),
    )


class TestOidcStateRepository(unittest.TestCase):

    def setUp(self):
        self.db, self._db_path = _make_db()
        self.oidc_state_repo = OidcStateRepository(self.db)

    def tearDown(self):
        os.unlink(self._db_path)

    # ── Test 1: create + get_valid_by_state ───────────────────────────────────

    def test_create_and_get_valid_by_state(self):
        s = _make_state()
        self.oidc_state_repo.create(s)

        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertIsNotNone(found)
        self.assertEqual(found.id, s.id)
        self.assertEqual(found.nonce, s.nonce)
        self.assertIsNone(found.consumed_at)

    # ── Test 2: consumed state excluded ──────────────────────────────────────

    def test_get_valid_by_state_excludes_consumed(self):
        s = _make_state()
        self.oidc_state_repo.create(s)

        self.oidc_state_repo.mark_callback_consumed(
            state_id=s.id,
            exchange_code="ex_" + secrets.token_urlsafe(16),
            api_token_id=str(uuid.uuid4()),
            expires_at=_future_iso(60),
            consumed_at=utc_now_iso(),
        )

        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertIsNone(found, "Consumed state must not be returned by get_valid_by_state")

    # ── Test 3: expired state excluded ───────────────────────────────────────

    def test_get_valid_by_state_excludes_expired(self):
        s = _make_state(expires_at=_past_iso(60))
        self.oidc_state_repo.create(s)

        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertIsNone(found, "Expired state must not be returned by get_valid_by_state")

    # ── Test 4: mark_callback_consumed sets all fields ────────────────────────

    def test_mark_callback_consumed_sets_fields(self):
        s = _make_state()
        self.oidc_state_repo.create(s)

        exchange_code = "ex_" + secrets.token_urlsafe(16)
        api_token_id = str(uuid.uuid4())
        new_expires_at = _future_iso(60)
        consumed_at = utc_now_iso()

        self.oidc_state_repo.mark_callback_consumed(
            state_id=s.id,
            exchange_code=exchange_code,
            api_token_id=api_token_id,
            expires_at=new_expires_at,
            consumed_at=consumed_at,
        )

        found = self.oidc_state_repo.get_valid_by_exchange_code(exchange_code, utc_now_iso())
        self.assertIsNotNone(found)
        self.assertEqual(found.exchange_code, exchange_code)
        self.assertEqual(found.api_token_id, api_token_id)
        self.assertEqual(found.consumed_at, consumed_at)
        self.assertEqual(found.expires_at, new_expires_at)

    # ── Test 5: get_valid_by_exchange_code requires api_token_id IS NOT NULL ──

    def test_get_valid_by_exchange_code_requires_api_token_id_not_null(self):
        exchange_code = "orphan_" + secrets.token_urlsafe(16)
        now = utc_now_iso()
        future = _future_iso(60)

        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO oidc_states
                    (id, state, nonce, exchange_code, api_token_id,
                     created_at, expires_at, consumed_at)
                VALUES (?, ?, ?, ?, NULL, ?, ?, ?)
                """,
                (str(uuid.uuid4()), "orphan_state_" + secrets.token_urlsafe(8),
                 "nonce", exchange_code, now, future, now),
            )

        result = self.oidc_state_repo.get_valid_by_exchange_code(exchange_code, utc_now_iso())
        self.assertIsNone(result, "State with api_token_id IS NULL must not be returned")

    # ── Test 6: delete removes the row ────────────────────────────────────────

    def test_delete_removes_row(self):
        s = _make_state()
        self.oidc_state_repo.create(s)
        self.assertIsNotNone(self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso()))

        self.oidc_state_repo.delete(s.id)

        # Row gone: unique state value can be reinserted without IntegrityError
        s2 = _make_state(state_val=s.state)
        self.oidc_state_repo.create(s2)
        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertEqual(found.id, s2.id)

    # ── Test 7: delete_expired removes only expired rows ─────────────────────

    def test_delete_expired_removes_expired_states(self):
        expired = _make_state(expires_at=_past_iso(3600))
        self.oidc_state_repo.create(expired)

        self.oidc_state_repo.delete_expired(utc_now_iso())

        # Reuse the same unique state value: must succeed if row was deleted
        fresh = _make_state(state_val=expired.state, expires_at=_future_iso(600))
        self.oidc_state_repo.create(fresh)
        self.assertIsNotNone(
            self.oidc_state_repo.get_valid_by_state(expired.state, utc_now_iso())
        )

    def test_delete_expired_keeps_valid_states(self):
        valid = _make_state(expires_at=_future_iso(600))
        self.oidc_state_repo.create(valid)

        self.oidc_state_repo.delete_expired(utc_now_iso())

        found = self.oidc_state_repo.get_valid_by_state(valid.state, utc_now_iso())
        self.assertIsNotNone(found, "Valid state must survive delete_expired")
        self.assertEqual(found.id, valid.id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
