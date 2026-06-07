#!/usr/bin/env python3
"""
Unit tests: OidcStateRepository (SQLite).

Covers:
  1.  create + get_valid_by_state
  2.  get_valid_by_state excludes consumed states
  3.  get_valid_by_state excludes expired states
  4.  get_valid_by_state excludes states without provider_id (legacy/pre-migration)
  5.  mark_callback_consumed sets exchange_code/user_id/consumed_at/expires_at
  6.  provider_id is preserved through mark_callback_consumed
  7.  get_valid_by_exchange_code requires user_id IS NOT NULL
  8.  get_valid_by_exchange_code rejects exchange codes without provider_id
  9.  delete removes the row
  10. delete_expired removes only expired states
  11. delete_expired keeps valid states

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


def _make_state(
    state_val: str | None = None,
    expires_at: str | None = None,
    provider_id: str | None = None,
) -> OidcState:
    now = utc_now_iso()
    return OidcState(
        id=str(uuid.uuid4()),
        state=state_val or ("state_" + secrets.token_urlsafe(16)),
        nonce="nonce_" + secrets.token_urlsafe(16),
        created_at=now,
        expires_at=expires_at or _future_iso(600),
        provider_id=provider_id or str(uuid.uuid4()),
    )


class TestOidcStateRepository(unittest.TestCase):

    def setUp(self):
        self.db, self._db_path = _make_db()
        self.oidc_state_repo = OidcStateRepository(self.db)

    def tearDown(self):
        os.unlink(self._db_path)

    # ── 1. create + get_valid_by_state ────────────────────────────────────────

    def test_create_and_get_valid_by_state(self):
        s = _make_state()
        self.oidc_state_repo.create(s)

        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertIsNotNone(found)
        self.assertEqual(found.id, s.id)
        self.assertEqual(found.nonce, s.nonce)
        self.assertEqual(found.provider_id, s.provider_id)
        self.assertIsNone(found.consumed_at)

    # ── 2. consumed state excluded ────────────────────────────────────────────

    def test_get_valid_by_state_excludes_consumed(self):
        s = _make_state()
        self.oidc_state_repo.create(s)

        self.oidc_state_repo.mark_callback_consumed(
            state_id=s.id,
            exchange_code="ex_" + secrets.token_urlsafe(16),
            user_id=str(uuid.uuid4()),
            expires_at=_future_iso(60),
            consumed_at=utc_now_iso(),
        )

        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertIsNone(found, "Consumed state must not be returned by get_valid_by_state")

    # ── 3. expired state excluded ─────────────────────────────────────────────

    def test_get_valid_by_state_excludes_expired(self):
        s = _make_state(expires_at=_past_iso(60))
        self.oidc_state_repo.create(s)

        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertIsNone(found, "Expired state must not be returned by get_valid_by_state")

    # ── 4. state without provider_id rejected (legacy/pre-migration rows) ─────

    def test_get_valid_by_state_rejects_state_without_provider_id(self):
        raw_state = "state_" + secrets.token_urlsafe(16)
        now = utc_now_iso()
        future = _future_iso(600)

        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO oidc_states
                    (id, state, nonce, exchange_code, user_id,
                     created_at, expires_at, consumed_at, provider_id)
                VALUES (?, ?, ?, NULL, NULL, ?, ?, NULL, NULL)
                """,
                (str(uuid.uuid4()), raw_state, "nonce_legacy", now, future),
            )

        result = self.oidc_state_repo.get_valid_by_state(raw_state, utc_now_iso())
        self.assertIsNone(result, "State with provider_id IS NULL must be rejected")

    # ── 5. mark_callback_consumed sets all fields ─────────────────────────────

    def test_mark_callback_consumed_sets_fields(self):
        s = _make_state()
        self.oidc_state_repo.create(s)

        exchange_code = "ex_" + secrets.token_urlsafe(16)
        user_id = str(uuid.uuid4())
        new_expires_at = _future_iso(60)
        consumed_at = utc_now_iso()

        self.oidc_state_repo.mark_callback_consumed(
            state_id=s.id,
            exchange_code=exchange_code,
            user_id=user_id,
            expires_at=new_expires_at,
            consumed_at=consumed_at,
        )

        found = self.oidc_state_repo.get_valid_by_exchange_code(exchange_code, utc_now_iso())
        self.assertIsNotNone(found)
        self.assertEqual(found.exchange_code, exchange_code)
        self.assertEqual(found.user_id, user_id)
        self.assertEqual(found.consumed_at, consumed_at)
        self.assertEqual(found.expires_at, new_expires_at)

    # ── 6. provider_id preserved through mark_callback_consumed ───────────────

    def test_provider_id_preserved_through_callback_consumed(self):
        provider_id = str(uuid.uuid4())
        s = _make_state(provider_id=provider_id)
        self.oidc_state_repo.create(s)

        exchange_code = "ex_" + secrets.token_urlsafe(16)
        self.oidc_state_repo.mark_callback_consumed(
            state_id=s.id,
            exchange_code=exchange_code,
            user_id=str(uuid.uuid4()),
            expires_at=_future_iso(60),
            consumed_at=utc_now_iso(),
        )

        found = self.oidc_state_repo.get_valid_by_exchange_code(exchange_code, utc_now_iso())
        self.assertIsNotNone(found)
        self.assertEqual(found.provider_id, provider_id,
                         "provider_id must survive mark_callback_consumed unchanged")

    # ── 7. get_valid_by_exchange_code requires user_id IS NOT NULL ────────────

    def test_get_valid_by_exchange_code_requires_user_id_not_null(self):
        exchange_code = "orphan_" + secrets.token_urlsafe(16)
        now = utc_now_iso()
        future = _future_iso(60)

        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO oidc_states
                    (id, state, nonce, exchange_code, user_id,
                     created_at, expires_at, consumed_at, provider_id)
                VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    "orphan_state_" + secrets.token_urlsafe(8),
                    "nonce",
                    exchange_code,
                    now, future, now,
                    str(uuid.uuid4()),
                ),
            )

        result = self.oidc_state_repo.get_valid_by_exchange_code(exchange_code, utc_now_iso())
        self.assertIsNone(result, "State with user_id IS NULL must not be returned")

    # ── 8. get_valid_by_exchange_code rejects exchange without provider_id ────

    def test_get_valid_by_exchange_code_rejects_exchange_without_provider_id(self):
        exchange_code = "legacy_ex_" + secrets.token_urlsafe(16)
        now = utc_now_iso()
        future = _future_iso(60)

        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO oidc_states
                    (id, state, nonce, exchange_code, user_id,
                     created_at, expires_at, consumed_at, provider_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    str(uuid.uuid4()),
                    "state_" + secrets.token_urlsafe(8),
                    "nonce",
                    exchange_code,
                    str(uuid.uuid4()),
                    now, future, now,
                ),
            )

        result = self.oidc_state_repo.get_valid_by_exchange_code(exchange_code, utc_now_iso())
        self.assertIsNone(result, "Exchange code with provider_id IS NULL must be rejected")

    # ── 9. delete removes the row ─────────────────────────────────────────────

    def test_delete_removes_row(self):
        s = _make_state()
        self.oidc_state_repo.create(s)
        self.assertIsNotNone(self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso()))

        self.oidc_state_repo.delete(s.id)

        s2 = _make_state(state_val=s.state)
        self.oidc_state_repo.create(s2)
        found = self.oidc_state_repo.get_valid_by_state(s.state, utc_now_iso())
        self.assertEqual(found.id, s2.id)

    # ── 10. delete_expired removes only expired rows ──────────────────────────

    def test_delete_expired_removes_expired_states(self):
        expired = _make_state(expires_at=_past_iso(3600))
        self.oidc_state_repo.create(expired)

        self.oidc_state_repo.delete_expired(utc_now_iso())

        fresh = _make_state(state_val=expired.state, expires_at=_future_iso(600))
        self.oidc_state_repo.create(fresh)
        self.assertIsNotNone(
            self.oidc_state_repo.get_valid_by_state(expired.state, utc_now_iso())
        )

    # ── 11. delete_expired keeps valid states ─────────────────────────────────

    def test_delete_expired_keeps_valid_states(self):
        valid = _make_state(expires_at=_future_iso(600))
        self.oidc_state_repo.create(valid)

        self.oidc_state_repo.delete_expired(utc_now_iso())

        found = self.oidc_state_repo.get_valid_by_state(valid.state, utc_now_iso())
        self.assertIsNotNone(found, "Valid state must survive delete_expired")
        self.assertEqual(found.id, valid.id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
