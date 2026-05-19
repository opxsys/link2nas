from backend.models.notification_config import NotificationConfig


class PostgresNotificationConfigRepository:
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
            with conn.cursor() as cur:
                if config.is_default:
                    cur.execute(
                        """
                        UPDATE notification_configs
                        SET is_default = FALSE,
                            updated_at = %s
                        WHERE user_id = %s
                          AND channel = %s
                        """,
                        (config.updated_at, config.user_id, config.channel),
                    )

                cur.execute(
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        config.id,
                        config.user_id,
                        config.name,
                        config.channel,
                        bool(config.is_enabled),
                        bool(config.is_default),
                        config.config_json,
                        config.created_at,
                        config.updated_at,
                    ),
                )
            conn.commit()

        return config

    def update(self, config: NotificationConfig) -> NotificationConfig:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                if config.is_default:
                    cur.execute(
                        """
                        UPDATE notification_configs
                        SET is_default = FALSE,
                            updated_at = %s
                        WHERE user_id = %s
                          AND channel = %s
                          AND id != %s
                        """,
                        (config.updated_at, config.user_id, config.channel, config.id),
                    )

                cur.execute(
                    """
                    UPDATE notification_configs
                    SET
                        name = %s,
                        channel = %s,
                        is_enabled = %s,
                        is_default = %s,
                        config_json = %s,
                        updated_at = %s
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (
                        config.name,
                        config.channel,
                        bool(config.is_enabled),
                        bool(config.is_default),
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
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM notification_configs
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (config_id, user_id),
                )
                deleted = cur.rowcount > 0
            conn.commit()

        return deleted

    def get_by_id(self, user_id: str, config_id: str) -> NotificationConfig | None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_configs
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (config_id, user_id),
                )
                row = cur.fetchone()

        return self._row_to_config(row) if row else None

    def get_default_for_channel(self, user_id: str, channel: str) -> NotificationConfig | None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_configs
                    WHERE user_id = %s
                      AND channel = %s
                      AND is_enabled = TRUE
                      AND is_default = TRUE
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """,
                    (user_id, channel),
                )
                row = cur.fetchone()

        return self._row_to_config(row) if row else None

    def list_for_user(self, user_id: str) -> list[NotificationConfig]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_configs
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    """,
                    (user_id,),
                )
                rows = cur.fetchall()

        return [self._row_to_config(row) for row in rows]

    def list_enabled_for_user(self, user_id: str) -> list[NotificationConfig]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_configs
                    WHERE user_id = %s
                      AND is_enabled = TRUE
                    ORDER BY created_at DESC
                    """,
                    (user_id,),
                )
                rows = cur.fetchall()

        return [self._row_to_config(row) for row in rows]