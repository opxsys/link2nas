from backend.models.user_integration_settings import UserIntegrationSettings


class UserIntegrationSettingsRepository:
    def __init__(self, db):
        self.db = db

    def get_for_user(self, user_id: str) -> UserIntegrationSettings | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM user_integration_settings
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

        return self._map_row(row)

    def upsert(self, settings: UserIntegrationSettings) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO user_integration_settings (
                    user_id,
                    prowlarr_enabled,
                    prowlarr_url,
                    prowlarr_open_mode,
                    home_page,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    prowlarr_enabled = excluded.prowlarr_enabled,
                    prowlarr_url = excluded.prowlarr_url,
                    prowlarr_open_mode = excluded.prowlarr_open_mode,
                    home_page = excluded.home_page,
                    updated_at = excluded.updated_at
                """,
                (
                    settings.user_id,
                    1 if settings.prowlarr_enabled else 0,
                    settings.prowlarr_url or "",
                    settings.prowlarr_open_mode,
                    settings.home_page,
                    settings.created_at,
                    settings.updated_at,
                ),
            )

    def _map_row(self, row) -> UserIntegrationSettings | None:
        if row is None:
            return None

        return UserIntegrationSettings(
            user_id=row["user_id"],
            prowlarr_enabled=bool(row["prowlarr_enabled"]),
            prowlarr_url=row["prowlarr_url"] or "",
            prowlarr_open_mode=row["prowlarr_open_mode"] or "both",
            home_page=row["home_page"] or "jobs",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
