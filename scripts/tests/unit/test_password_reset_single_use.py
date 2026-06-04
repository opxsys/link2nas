#!/usr/bin/env python3
"""
Unit test: password_reset token is strictly single-use and invalidates sibling tokens.

Covers:
  - First confirm succeeds and changes the password.
  - Second confirm with the same token fails with "Token already used".
  - Concurrent confirm (simulated) cannot both succeed.
  - Expired tokens are rejected.
  - Wrong token type is rejected.
  - After a successful reset, all other unused password_reset tokens for the same
    user are also invalidated (consume_other_unused_tokens_for_user_type).
  - Other token types (magic_login) for the same user are NOT invalidated.

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


    # ── invalidation of sibling tokens ────────────────────────────────────────

    def _create_reset_token_directly(self, user_id: str) -> str:
        """Bypass service cleanup to insert a second unused password_reset token."""
        from backend.models.account_token import AccountToken
        import uuid
        from datetime import UTC, datetime, timedelta

        raw = self.svc.generate_raw_token()
        expires_at = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        t = AccountToken(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash=self.svc.hash_token(raw),
            token_type="password_reset",
            expires_at=expires_at,
            used_at=None,
            created_at=utc_now_iso(),
            created_by_user_id=None,
            metadata_json="{}",
        )
        self.token_repo.create(t)
        return raw

    def _create_magic_login_token_directly(self, user_id: str) -> str:
        """Insert an unused magic_login token for the same user."""
        from backend.models.account_token import AccountToken
        import uuid
        from datetime import UTC, datetime, timedelta

        raw = self.svc.generate_raw_token()
        expires_at = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
        t = AccountToken(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash=self.svc.hash_token(raw),
            token_type="magic_login",
            expires_at=expires_at,
            used_at=None,
            created_at=utc_now_iso(),
            created_by_user_id=None,
            metadata_json="{}",
        )
        self.token_repo.create(t)
        return raw

    def test_sibling_reset_tokens_invalidated_after_confirm(self):
        """A second password_reset token for the same user is invalidated after successful reset."""
        # Create first token via service (normal path)
        raw_first = self._create_reset_token()

        # Insert a second token directly (bypassing service cleanup)
        raw_second = self._create_reset_token_directly(self.user.id)

        # Confirm via first token
        token = self.svc.get_valid_token(raw_first, expected_type="password_reset")
        self.assertTrue(self.svc.consume_token_once(token))

        # Simulate successful reset, then invalidate sibling tokens
        invalidated = self.svc.consume_other_unused_tokens_for_user_type(
            user_id=self.user.id,
            token_type="password_reset",
            exclude_token_id=token.id,
        )
        self.assertEqual(invalidated, 1, "One sibling token must have been invalidated")

        # Second token must now be rejected
        with self.assertRaises(AccountTokenError) as ctx:
            self.svc.get_valid_token(raw_second, expected_type="password_reset")
        self.assertIn("already used", str(ctx.exception).lower())

    def test_magic_login_token_not_invalidated_after_reset(self):
        """A magic_login token for the same user is NOT invalidated by a password reset."""
        raw_reset = self._create_reset_token()
        raw_magic = self._create_magic_login_token_directly(self.user.id)

        # Confirm password reset
        token = self.svc.get_valid_token(raw_reset, expected_type="password_reset")
        self.assertTrue(self.svc.consume_token_once(token))
        self.svc.consume_other_unused_tokens_for_user_type(
            user_id=self.user.id,
            token_type="password_reset",
            exclude_token_id=token.id,
        )

        # magic_login token must still be valid
        magic_token = self.svc.get_valid_token(raw_magic, expected_type="magic_login")
        self.assertIsNotNone(magic_token)

    def test_invalidated_count_matches_sibling_count(self):
        """Return value equals the number of additional tokens that were actually invalidated."""
        # Create three sibling tokens directly (plus one via service first)
        raw_via_service = self._create_reset_token()
        raw_b = self._create_reset_token_directly(self.user.id)
        raw_c = self._create_reset_token_directly(self.user.id)

        # Consume the service token
        token = self.svc.get_valid_token(raw_via_service, expected_type="password_reset")
        self.assertTrue(self.svc.consume_token_once(token))

        # Two siblings (raw_b, raw_c) must be invalidated
        invalidated = self.svc.consume_other_unused_tokens_for_user_type(
            user_id=self.user.id,
            token_type="password_reset",
            exclude_token_id=token.id,
        )
        self.assertEqual(invalidated, 2)

        # Confirm neither raw_b nor raw_c works anymore
        for raw in (raw_b, raw_c):
            with self.assertRaises(AccountTokenError):
                self.svc.get_valid_token(raw, expected_type="password_reset")


if __name__ == "__main__":
    unittest.main(verbosity=2)
