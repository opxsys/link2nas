from backend.models.account_token import AccountToken


class AccountTokenRepository:
    def __init__(self, db):
        self.db = db

    def create(self, token: AccountToken) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO account_tokens (
                    id, user_id, token_hash, token_type,
                    expires_at, used_at, created_at, created_by_user_id,
                    metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token.id,
                    token.user_id,
                    token.token_hash,
                    token.token_type,
                    token.expires_at,
                    token.used_at,
                    token.created_at,
                    token.created_by_user_id,
                    token.metadata_json,
                ),
            )

    def get_by_hash(self, token_hash: str) -> AccountToken | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM account_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()

        return self._map_row(row)

    def mark_used(self, token_id: str, used_at: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE account_tokens
                SET used_at = ?
                WHERE id = ?
                """,
                (used_at, token_id),
            )

    def mark_used_if_unused(self, token_id: str, used_at: str) -> int:
        """Atomic single-use guard. Returns 1 if consumed, 0 if already used."""
        with self.db.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE account_tokens
                SET used_at = ?
                WHERE id = ?
                  AND used_at IS NULL
                """,
                (used_at, token_id),
            )
            return int(cursor.rowcount or 0)

    def delete_unused_for_user_type(self, user_id: str, token_type: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                DELETE FROM account_tokens
                WHERE user_id = ?
                  AND token_type = ?
                  AND used_at IS NULL
                """,
                (user_id, token_type),
            )

    def cleanup_old_tokens(self, cutoff_iso: str) -> int:
        with self.db.connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM account_tokens
                WHERE expires_at <= ?
                   OR (used_at IS NOT NULL AND used_at <= ?)
                """,
                (cutoff_iso, cutoff_iso),
            )

            return int(cursor.rowcount or 0)
            
    def _map_row(self, row) -> AccountToken | None:
        if row is None:
            return None

        return AccountToken(
            id=row["id"],
            user_id=row["user_id"],
            token_hash=row["token_hash"],
            token_type=row["token_type"],
            expires_at=row["expires_at"],
            used_at=row["used_at"],
            created_at=row["created_at"],
            created_by_user_id=row["created_by_user_id"],
            metadata_json=row["metadata_json"],
        )

