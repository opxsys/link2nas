from backend.models.oidc_state import OidcState


class OidcStateRepository:
    def __init__(self, db):
        self.db = db

    def create(self, state: OidcState) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO oidc_states (
                    id, state, nonce, exchange_code, user_id,
                    created_at, expires_at, consumed_at, provider_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    state.id,
                    state.state,
                    state.nonce,
                    state.exchange_code,
                    state.user_id,
                    state.created_at,
                    state.expires_at,
                    state.consumed_at,
                    state.provider_id,
                ),
            )

    def get_valid_by_state(self, state: str, now_iso: str) -> OidcState | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM oidc_states
                WHERE state = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                  AND provider_id IS NOT NULL
                """,
                (state, now_iso),
            ).fetchone()

        if row is None:
            return None

        return self._map_row(row)

    def mark_callback_consumed(
        self,
        state_id: str,
        exchange_code: str,
        user_id: str,
        expires_at: str,
        consumed_at: str,
    ) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE oidc_states
                SET consumed_at = ?,
                    exchange_code = ?,
                    user_id = ?,
                    expires_at = ?
                WHERE id = ?
                """,
                (consumed_at, exchange_code, user_id, expires_at, state_id),
            )

    def get_valid_by_exchange_code(self, exchange_code: str, now_iso: str) -> OidcState | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM oidc_states
                WHERE exchange_code = ?
                  AND consumed_at IS NOT NULL
                  AND user_id IS NOT NULL
                  AND provider_id IS NOT NULL
                  AND expires_at > ?
                """,
                (exchange_code, now_iso),
            ).fetchone()

        if row is None:
            return None

        return self._map_row(row)

    def delete(self, state_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM oidc_states WHERE id = ?",
                (state_id,),
            )

    def delete_expired(self, now_iso: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM oidc_states WHERE expires_at < ?",
                (now_iso,),
            )

    def _map_row(self, row) -> OidcState:
        return OidcState(
            id=row["id"],
            state=row["state"],
            nonce=row["nonce"],
            exchange_code=row["exchange_code"],
            user_id=row["user_id"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            consumed_at=row["consumed_at"],
            provider_id=row["provider_id"],
        )
