from backend.models.api_token import ApiToken


class ApiTokenRepository:
    def __init__(self, db):
        self.db = db

    def create(self, token: ApiToken) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO api_tokens (
                    id, user_id, token, label,
                    is_active, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    token.id,
                    token.user_id,
                    token.token,
                    token.label,
                    token.is_active,
                    token.created_at,
                    token.updated_at,
                ),
            )

    def get_active_by_token(self, token: str) -> ApiToken | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM api_tokens
                WHERE token = %s AND is_active = TRUE
                """,
                (token,),
            ).fetchone()

        if row is None:
            return None

        return self._map_row(row)

    def list_for_user(self, user_id: str) -> list[ApiToken]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM api_tokens
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()

        return [self._map_row(row) for row in rows]

    def deactivate(self, user_id: str, token_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE api_tokens
                SET is_active = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND user_id = %s
                """,
                (token_id, user_id),
            )

    def _map_row(self, row) -> ApiToken:
        return ApiToken(
            id=row["id"],
            user_id=row["user_id"],
            token=row["token"],
            label=row["label"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
