from backend.models.email_template import EmailTemplate


class EmailTemplateRepository:
    def __init__(self, db):
        self.db = db

    def get(self, template_key: str, language: str) -> EmailTemplate | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM email_templates
                WHERE template_key = ? AND language = ?
                """,
                (template_key, language),
            ).fetchone()
        return self._map_row(row)

    def list_all(self) -> list[EmailTemplate]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM email_templates
                ORDER BY template_key, language
                """
            ).fetchall()
        return [self._map_row(row) for row in rows]

    def upsert(self, t: EmailTemplate) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO email_templates (
                    id, template_key, language,
                    subject_template, body_template,
                    is_custom, created_at, updated_at, updated_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (template_key, language) DO UPDATE SET
                    subject_template = excluded.subject_template,
                    body_template = excluded.body_template,
                    is_custom = excluded.is_custom,
                    updated_at = excluded.updated_at,
                    updated_by_user_id = excluded.updated_by_user_id
                """,
                (
                    t.id, t.template_key, t.language,
                    t.subject_template, t.body_template,
                    1 if t.is_custom else 0,
                    t.created_at, t.updated_at, t.updated_by_user_id,
                ),
            )

    def insert_if_absent(self, t: EmailTemplate) -> None:
        """Used by ensure_defaults — never overwrites an existing row."""
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO email_templates (
                    id, template_key, language,
                    subject_template, body_template,
                    is_custom, created_at, updated_at, updated_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (template_key, language) DO NOTHING
                """,
                (
                    t.id, t.template_key, t.language,
                    t.subject_template, t.body_template,
                    1 if t.is_custom else 0,
                    t.created_at, t.updated_at, t.updated_by_user_id,
                ),
            )

    def _map_row(self, row) -> EmailTemplate | None:
        if row is None:
            return None
        return EmailTemplate(
            id=row["id"],
            template_key=row["template_key"],
            language=row["language"],
            subject_template=row["subject_template"],
            body_template=row["body_template"],
            is_custom=bool(row["is_custom"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            updated_by_user_id=row["updated_by_user_id"],
        )
