from backend.models.app_setting import AppSetting


class AppSettingsRepository:
    def __init__(self, db):
        self.db = db

    def get(self, key: str) -> AppSetting | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM app_settings
                WHERE key = %s
                """,
                (key,),
            ).fetchone()

        return self._map_row(row)

    def list_all(self) -> list[AppSetting]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM app_settings
                ORDER BY key ASC
                """
            ).fetchall()

        return [self._map_row(row) for row in rows]

    def upsert(self, setting: AppSetting) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO app_settings (
                    key,
                    value_json,
                    updated_at
                )
                VALUES (%s, %s, %s)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (
                    setting.key,
                    setting.value_json,
                    setting.updated_at,
                ),
            )

    def _map_row(self, row) -> AppSetting | None:
        if row is None:
            return None

        return AppSetting(
            key=row["key"],
            value_json=row["value_json"],
            updated_at=row["updated_at"],
        )

