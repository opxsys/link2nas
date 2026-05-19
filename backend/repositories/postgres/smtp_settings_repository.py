from backend.models.smtp_settings import SmtpSettings


class SmtpSettingsRepository:
    def __init__(self, db):
        self.db = db

    def get(self) -> SmtpSettings | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM smtp_settings
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()

        return self._map_row(row)

    def upsert(self, settings: SmtpSettings) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO smtp_settings (
                    id,
                    enabled,
                    host,
                    port,
                    username,
                    encrypted_password,
                    from_email,
                    from_name,
                    use_tls,
                    use_ssl,
                    created_at,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(id) DO UPDATE SET
                    enabled = excluded.enabled,
                    host = excluded.host,
                    port = excluded.port,
                    username = excluded.username,
                    encrypted_password = excluded.encrypted_password,
                    from_email = excluded.from_email,
                    from_name = excluded.from_name,
                    use_tls = excluded.use_tls,
                    use_ssl = excluded.use_ssl,
                    updated_at = excluded.updated_at
                """,
                (
                    settings.id,
                    settings.enabled,
                    settings.host,
                    settings.port,
                    settings.username,
                    settings.encrypted_password,
                    settings.from_email,
                    settings.from_name,
                    settings.use_tls,
                    settings.use_ssl,
                    settings.created_at,
                    settings.updated_at,
                ),
            )

    def _map_row(self, row) -> SmtpSettings | None:
        if row is None:
            return None

        return SmtpSettings(
            id=row["id"],
            enabled=bool(row["enabled"]),
            host=row["host"],
            port=int(row["port"]),
            username=row["username"],
            encrypted_password=row["encrypted_password"],
            from_email=row["from_email"],
            from_name=row["from_name"],
            use_tls=bool(row["use_tls"]),
            use_ssl=bool(row["use_ssl"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
