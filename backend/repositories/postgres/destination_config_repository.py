from backend.models.destination_config import DestinationConfig


class DestinationConfigRepository:
    def __init__(self, db):
        self.db = db

    def upsert(self, config: DestinationConfig) -> None:
        with self.db.connect() as conn:
            if config.is_default:
                conn.execute(
                    """
                    UPDATE destination_configs
                    SET is_default = FALSE
                    WHERE user_id = %s
                    """,
                    (config.user_id,),
                )

            conn.execute(
                """
                INSERT INTO destination_configs (
                    id, user_id, destination_type, name,
                    is_enabled, is_default,
                    config_json,
                    created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(id)
                DO UPDATE SET
                    destination_type = excluded.destination_type,
                    name = excluded.name,
                    is_enabled = excluded.is_enabled,
                    is_default = excluded.is_default,
                    config_json = excluded.config_json,
                    updated_at = excluded.updated_at
                """,
                (
                    config.id,
                    config.user_id,
                    config.destination_type,
                    config.name,
                    config.is_enabled,
                    config.is_default,
                    config.config_json,
                    config.created_at,
                    config.updated_at,
                ),
            )

    def get_by_id(self, user_id: str, config_id: str) -> DestinationConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM destination_configs
                WHERE user_id = %s AND id = %s
                """,
                (user_id, config_id),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def get_by_name(self, user_id: str, name: str) -> DestinationConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM destination_configs
                WHERE user_id = %s AND name = %s
                """,
                (user_id, name),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def get_default(self, user_id: str) -> DestinationConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM destination_configs
                WHERE user_id = %s
                  AND is_enabled = TRUE
                  AND is_default = TRUE
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def get(self, user_id: str, destination_name: str) -> DestinationConfig | None:
        destination_type = str(destination_name or "").strip().lower()
        if destination_type == "nas":
            destination_type = "synology"

        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM destination_configs
                WHERE user_id = %s
                  AND destination_type = %s
                ORDER BY is_default DESC, updated_at DESC
                LIMIT 1
                """,
                (user_id, destination_type),
            ).fetchone()

        return self._map_row(row) if row is not None else None

    def list_for_user(self, user_id: str) -> list[DestinationConfig]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM destination_configs
                WHERE user_id = %s
                ORDER BY is_default DESC, name ASC
                """,
                (user_id,),
            ).fetchall()

        return [self._map_row(r) for r in rows]

    def delete(self, user_id: str, config_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                DELETE FROM destination_configs
                WHERE user_id = %s AND id = %s
                """,
                (user_id, config_id),
            )

    def _map_row(self, row) -> DestinationConfig:
        return DestinationConfig(
            id=row["id"],
            user_id=row["user_id"],
            destination_type=row["destination_type"],
            name=row["name"],
            is_enabled=bool(row["is_enabled"]),
            is_default=bool(row["is_default"]),
            config_json=row["config_json"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
