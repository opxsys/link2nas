from backend.models.notification_config import NotificationConfig


class SQLiteNotificationConfigRepository:
    def __init__(self, db):
        self.db = db

    def _row_to_config(self, row) -> NotificationConfig:
        return NotificationConfig(
            id=row["id"],
            user_id=row["user_id"],
            name=row["name"],
            channel=row["channel"],
            is_enabled=bool(row["is_enabled"]),
            is_default=bool(row["is_default"]),
            config_json=row["config_json"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def create(self, config: NotificationConfig) -> NotificationConfig:
        with self.db.connect() as conn:
            if config.is_default:
                conn.execute(
                    """
                    UPDATE notification_configs
                    SET is_default = 0,
                        updated_at = ?
                    WHERE user_id = ?
                      AND channel = ?
                    """,
                    (config.updated_at, config.user_id, config.channel),
                )

            conn.execute(
                """
                INSERT INTO notification_configs (
                    id,
                    user_id,
                    name,
                    channel,
                    is_enabled,
                    is_default,
                    config_json,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    config.id,
                    config.user_id,
                    config.name,
                    config.channel,
                    1 if config.is_enabled else 0,
                    1 if config.is_default else 0,
                    config.config_json,
                    config.created_at,
                    config.updated_at,
                ),
            )
            conn.commit()

        return config

    def update(self, config: NotificationConfig) -> NotificationConfig:
        with self.db.connect() as conn:
            if config.is_default:
                conn.execute(
                    """
                    UPDATE notification_configs
                    SET is_default = 0,
                        updated_at = ?
                    WHERE user_id = ?
                      AND channel = ?
                      AND id != ?
                    """,
                    (config.updated_at, config.user_id, config.channel, config.id),
                )

            conn.execute(
                """
                UPDATE notification_configs
                SET
                    name = ?,
                    channel = ?,
                    is_enabled = ?,
                    is_default = ?,
                    config_json = ?,
                    updated_at = ?
                WHERE id = ?
                  AND user_id = ?
                """,
                (
                    config.name,
                    config.channel,
                    1 if config.is_enabled else 0,
                    1 if config.is_default else 0,
                    config.config_json,
                    config.updated_at,
                    config.id,
                    config.user_id,
                ),
            )
            conn.commit()

        return config

    def delete(self, user_id: str, config_id: str) -> bool:
        with self.db.connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM notification_configs
                WHERE id = ?
                  AND user_id = ?
                """,
                (config_id, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_by_id(self, user_id: str, config_id: str) -> NotificationConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM notification_configs
                WHERE id = ?
                  AND user_id = ?
                """,
                (config_id, user_id),
            ).fetchone()

        return self._row_to_config(row) if row else None

    def get_default_for_channel(self, user_id: str, channel: str) -> NotificationConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM notification_configs
                WHERE user_id = ?
                  AND channel = ?
                  AND is_enabled = 1
                  AND is_default = 1
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (user_id, channel),
            ).fetchone()

        return self._row_to_config(row) if row else None

    def list_for_user(self, user_id: str) -> list[NotificationConfig]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM notification_configs
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()

        return [self._row_to_config(row) for row in rows]

    def list_enabled_for_user(self, user_id: str) -> list[NotificationConfig]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM notification_configs
                WHERE user_id = ?
                  AND is_enabled = 1
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()

        return [self._row_to_config(row) for row in rows]
