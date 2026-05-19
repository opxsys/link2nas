from backend.models.provider_config import ProviderConfig


class ProviderConfigRepository:
    def __init__(self, db):
        self.db = db

    def upsert(self, config: ProviderConfig) -> None:
        with self.db.connect() as conn:
            if config.is_default:
                conn.execute(
                    """
                    UPDATE provider_configs
                    SET is_default = 0
                    WHERE user_id = ?
                    """,
                    (config.user_id,),
                )

            conn.execute(
                """
                INSERT INTO provider_configs (
                    id, user_id, provider_type, name,
                    is_enabled, is_default,
                    encrypted_api_key, account_expires_at,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id)
                DO UPDATE SET
                    provider_type = excluded.provider_type,
                    name = excluded.name,
                    is_enabled = excluded.is_enabled,
                    is_default = excluded.is_default,
                    encrypted_api_key = excluded.encrypted_api_key,
                    account_expires_at = excluded.account_expires_at,
                    updated_at = excluded.updated_at
                """,
                (
                    config.id,
                    config.user_id,
                    config.provider_type,
                    config.name,
                    1 if config.is_enabled else 0,
                    1 if config.is_default else 0,
                    config.encrypted_api_key,
                    config.account_expires_at,
                    config.created_at,
                    config.updated_at,
                ),
            )

    def get_by_id(self, user_id: str, config_id: str) -> ProviderConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM provider_configs
                WHERE user_id = ? AND id = ?
                """,
                (user_id, config_id),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def get_by_name(self, user_id: str, name: str) -> ProviderConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM provider_configs
                WHERE user_id = ? AND name = ?
                """,
                (user_id, name),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def get_default(self, user_id: str) -> ProviderConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM provider_configs
                WHERE user_id = ?
                  AND is_enabled = 1
                  AND is_default = 1
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def get(self, user_id: str, provider_name: str) -> ProviderConfig | None:
        provider_type = str(provider_name or "").strip().lower()

        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM provider_configs
                WHERE user_id = ?
                  AND provider_type = ?
                ORDER BY is_default DESC, updated_at DESC
                LIMIT 1
                """,
                (user_id, provider_type),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def list_for_user(self, user_id: str) -> list[ProviderConfig]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM provider_configs
                WHERE user_id = ?
                ORDER BY is_default DESC, name ASC
                """,
                (user_id,),
            ).fetchall()

        return [self._map_row(r) for r in rows]

    def update_account_expires_at(
        self,
        user_id: str,
        config_id: str,
        account_expires_at: str | None,
        updated_at: str,
    ) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE provider_configs
                SET account_expires_at = ?,
                    updated_at = ?
                WHERE user_id = ? AND id = ?
                """,
                (
                    account_expires_at,
                    updated_at,
                    user_id,
                    config_id,
                ),
            )

    def delete(self, user_id: str, config_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                DELETE FROM provider_configs
                WHERE user_id = ? AND id = ?
                """,
                (user_id, config_id),
            )

    def _map_row(self, row) -> ProviderConfig:
        return ProviderConfig(
            id=row["id"],
            user_id=row["user_id"],
            provider_type=row["provider_type"],
            name=row["name"],
            is_enabled=bool(row["is_enabled"]),
            is_default=bool(row["is_default"]),
            encrypted_api_key=row["encrypted_api_key"],
            account_expires_at=row["account_expires_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
