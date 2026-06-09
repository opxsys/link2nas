from backend.models.prowlarr_config import ProwlarrConfig


class ProwlarrConfigRepository:
    def __init__(self, db):
        self.db = db

    def get_global(self) -> ProwlarrConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM prowlarr_configs WHERE scope = 'global' LIMIT 1"
            ).fetchone()
        return self._map_row(row)

    def get_for_user(self, user_id: str) -> ProwlarrConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM prowlarr_configs WHERE scope = 'user' AND user_id = %s LIMIT 1",
                (user_id,),
            ).fetchone()
        return self._map_row(row)

    def upsert(self, config: ProwlarrConfig) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO prowlarr_configs (
                    id, scope, user_id, enabled, base_url, encrypted_api_key, label,
                    tested_at, last_test_status, last_test_message, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(id) DO UPDATE SET
                    enabled           = excluded.enabled,
                    base_url          = excluded.base_url,
                    encrypted_api_key = excluded.encrypted_api_key,
                    label             = excluded.label,
                    tested_at         = excluded.tested_at,
                    last_test_status  = excluded.last_test_status,
                    last_test_message = excluded.last_test_message,
                    updated_at        = excluded.updated_at
                """,
                (
                    config.id,
                    config.scope,
                    config.user_id,
                    config.enabled,
                    config.base_url,
                    config.encrypted_api_key,
                    config.label,
                    config.tested_at,
                    config.last_test_status,
                    config.last_test_message,
                    config.created_at,
                    config.updated_at,
                ),
            )

    def delete_global(self) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM prowlarr_configs WHERE scope = 'global'")

    def delete_for_user(self, user_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM prowlarr_configs WHERE scope = 'user' AND user_id = %s",
                (user_id,),
            )

    def _map_row(self, row) -> ProwlarrConfig | None:
        if row is None:
            return None
        return ProwlarrConfig(
            id=row["id"],
            scope=row["scope"],
            user_id=row["user_id"],
            enabled=bool(row["enabled"]),
            base_url=row["base_url"],
            encrypted_api_key=row["encrypted_api_key"],
            label=row["label"],
            tested_at=row["tested_at"],
            last_test_status=row["last_test_status"],
            last_test_message=row["last_test_message"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
