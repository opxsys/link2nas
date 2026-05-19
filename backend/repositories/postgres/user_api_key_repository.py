from backend.models.user_api_key import UserApiKey


class UserApiKeyRepository:
    def __init__(self, db):
        self.db = db

    def _row_to_key(self, row) -> UserApiKey:
        return UserApiKey(
            id=row["id"],
            user_id=row["user_id"],
            name=row["name"],
            key_prefix=row["key_prefix"],
            key_hash=row["key_hash"],
            scopes_json=row["scopes_json"],
            is_active=bool(row["is_active"]),
            revoked_at=row["revoked_at"],
            last_used_at=row["last_used_at"],
            last_used_ip=row["last_used_ip"],
            last_used_scope=row["last_used_scope"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def create(self, api_key: UserApiKey) -> UserApiKey:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_api_keys (
                        id,
                        user_id,
                        name,
                        key_prefix,
                        key_hash,
                        scopes_json,
                        is_active,
                        revoked_at,
                        last_used_at,
                        last_used_ip,
                        last_used_scope,
                        created_at,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        api_key.id,
                        api_key.user_id,
                        api_key.name,
                        api_key.key_prefix,
                        api_key.key_hash,
                        api_key.scopes_json,
                        bool(api_key.is_active),
                        api_key.revoked_at,
                        api_key.last_used_at,
                        api_key.last_used_ip,
                        api_key.last_used_scope,
                        api_key.created_at,
                        api_key.updated_at,
                    ),
                )
            conn.commit()

        return api_key

    def list_for_user(self, user_id: str) -> list[UserApiKey]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM user_api_keys
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    """,
                    (user_id,),
                )
                rows = cur.fetchall()

        return [self._row_to_key(row) for row in rows]

    def get_for_user(self, user_id: str, key_id: str) -> UserApiKey | None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM user_api_keys
                    WHERE user_id = %s
                      AND id = %s
                    """,
                    (user_id, key_id),
                )
                row = cur.fetchone()

        return self._row_to_key(row) if row else None

    def get_active_by_prefix(self, key_prefix: str) -> UserApiKey | None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM user_api_keys
                    WHERE key_prefix = %s
                      AND is_active = TRUE
                      AND revoked_at IS NULL
                    """,
                    (key_prefix,),
                )
                row = cur.fetchone()

        return self._row_to_key(row) if row else None

    def revoke(self, user_id: str, key_id: str, revoked_at: str) -> bool:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE user_api_keys
                    SET
                        is_active = FALSE,
                        revoked_at = %s,
                        updated_at = %s
                    WHERE user_id = %s
                      AND id = %s
                    """,
                    (revoked_at, revoked_at, user_id, key_id),
                )
                rowcount = cur.rowcount
            conn.commit()

        return rowcount > 0

    def delete(self, user_id: str, key_id: str) -> bool:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM user_api_keys
                    WHERE user_id = %s
                      AND id = %s
                    """,
                    (user_id, key_id),
                )
                rowcount = cur.rowcount
            conn.commit()

        return rowcount > 0

    def mark_used(
        self,
        key_id: str,
        used_at: str,
        ip: str | None = None,
        scope: str | None = None,
    ) -> None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE user_api_keys
                    SET
                        last_used_at = %s,
                        last_used_ip = %s,
                        last_used_scope = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (used_at, ip, scope, used_at, key_id),
                )
            conn.commit()
