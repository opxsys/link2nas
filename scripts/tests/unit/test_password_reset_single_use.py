#!/usr/bin/env python3
"""
Unit test: password_reset token is strictly single-use.

Covers:
  - First confirm succeeds and changes the password.
  - Second confirm with the same token fails with "Token already used".
  - Concurrent confirm (simulated) cannot both succeed.
  - Expired tokens are rejected.
  - Wrong token type is rejected.

Run from project root:
    python scripts/tests/unit/test_password_reset_single_use.py
    # or with unittest discovery:
    python -m unittest scripts.tests.unit.test_password_reset_single_use
"""

import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.storage.db import Database
from backend.repositories.sqlite.account_token_repository import AccountTokenRepository
from backend.repositories.sqlite.user_repository import UserRepository
from backend.services_v2.account_token_service import AccountTokenService, AccountTokenError
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
        password_hash="hashed_old",
    )


class TestPasswordResetSingleUse(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        db = Database(self._tmp.name)
        schema = os.path.join(_PROJECT_ROOT, "backend", "storage", "schema.sql")
        db.init_schema(schema)
        db.run_column_migrations()

        self.token_repo = AccountTokenRepository(db)
        self.user_repo = UserRepository(db)
        self.svc = AccountTokenService(
            token_repo=self.token_repo,
            public_base_url="https://example.com",
        )

        self.user = _make_user("user-001", "reset@example.com")
        self.user_repo.create(self.user)

    def tearDown(self):
        os.unlink(self._tmp.name)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _create_reset_token(self, ttl_hours=2):
        _, raw = self.svc.create_token(
            user_id=self.user.id,
            token_type="password_reset",
            created_by_user_id=None,
            ttl_hours=ttl_hours,
        )
        return raw

    # ── tests ─────────────────────────────────────────────────────────────────

    def test_first_confirm_succeeds(self):
        raw = self._create_reset_token()
        token = self.svc.get_valid_token(raw, expected_type="password_reset")
        consumed = self.svc.consume_token_once(token)
        self.assertTrue(consumed, "First consume must return True")

    def test_second_confirm_fails(self):
        raw = self._create_reset_token()

        # First confirm
        token = self.svc.get_valid_token(raw, expected_type="password_reset")
        self.assertTrue(self.svc.consume_token_once(token))

        # Second confirm with the same raw token: get_valid_token must reject it
        with self.assertRaises(AccountTokenError) as ctx:
            self.svc.get_valid_token(raw, expected_type="password_reset")
        self.assertIn("already used", str(ctx.exception).lower())

    def test_consume_token_once_is_idempotent_false(self):
        """consume_token_once called twice on the same token object returns False the second time."""
        raw = self._create_reset_token()
        token = self.svc.get_valid_token(raw, expected_type="password_reset")

        self.assertTrue(self.svc.consume_token_once(token))
        # Second call on same object: DB row already has used_at set → 0 rows affected
        self.assertFalse(self.svc.consume_token_once(token))

    def test_race_condition_only_one_wins(self):
        """Simulate two concurrent requests that both pass get_valid_token before either consumes."""
        raw = self._create_reset_token()

        # Both requests read the token before either consumes it
        token_a = self.svc.get_valid_token(raw, expected_type="password_reset")
        token_b = self.svc.get_valid_token(raw, expected_type="password_reset")

        # Only the first atomic consume wins
        result_a = self.svc.consume_token_once(token_a)
        result_b = self.svc.consume_token_once(token_b)

        winners = [r for r in (result_a, result_b) if r]
        self.assertEqual(len(winners), 1, "Exactly one concurrent consume must succeed")

    def test_expired_token_is_rejected(self):
        # Create a token that expired 1 second ago by writing directly to the repo
        raw = self.svc.generate_raw_token()
        past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()

        from backend.models.account_token import AccountToken
        import uuid
        t = AccountToken(
            id=str(uuid.uuid4()),
            user_id=self.user.id,
            token_hash=self.svc.hash_token(raw),
            token_type="password_reset",
            expires_at=past,
            used_at=None,
            created_at=utc_now_iso(),
            created_by_user_id=None,
            metadata_json="{}",
        )
        self.token_repo.create(t)

        with self.assertRaises(AccountTokenError) as ctx:
            self.svc.get_valid_token(raw, expected_type="password_reset")
        self.assertIn("expired", str(ctx.exception).lower())

    def test_wrong_token_type_is_rejected(self):
        raw = self._create_reset_token()
        with self.assertRaises(AccountTokenError):
            self.svc.get_valid_token(raw, expected_type="magic_login")

    def test_password_not_changed_on_second_attempt(self):
        """End-to-end: password hash written on first confirm cannot be overwritten via the same token."""
        raw = self._create_reset_token()

        # First confirm: consume token and write a sentinel hash
        token = self.svc.get_valid_token(raw, expected_type="password_reset")
        self.assertTrue(self.svc.consume_token_once(token))
        self.user.password_hash = "hash_after_first_reset"
        self.user_repo.update(self.user)

        # Verify sentinel is stored
        after_first = self.user_repo.get_by_id(self.user.id)
        self.assertEqual(after_first.password_hash, "hash_after_first_reset")

        # Second confirm attempt is rejected by get_valid_token (token already used)
        with self.assertRaises(AccountTokenError):
            self.svc.get_valid_token(raw, expected_type="password_reset")

        # Password hash must be unchanged (still the sentinel from the first confirm)
        after_second = self.user_repo.get_by_id(self.user.id)
        self.assertEqual(after_second.password_hash, "hash_after_first_reset")


if __name__ == "__main__":
    unittest.main(verbosity=2)
