from backend.models.announcement_read import AnnouncementRead


class AnnouncementReadRepository:
    def __init__(self, db):
        self.db = db

    def upsert(self, r: AnnouncementRead) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO announcement_reads (
                    id, announcement_id, user_id,
                    opened_at, read_at, acknowledged_at,
                    email_sent_at, email_status, email_error,
                    created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (announcement_id, user_id) DO UPDATE SET
                    opened_at = EXCLUDED.opened_at,
                    read_at = EXCLUDED.read_at,
                    acknowledged_at = EXCLUDED.acknowledged_at,
                    email_sent_at = EXCLUDED.email_sent_at,
                    email_status = EXCLUDED.email_status,
                    email_error = EXCLUDED.email_error,
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    r.id, r.announcement_id, r.user_id,
                    r.opened_at, r.read_at, r.acknowledged_at,
                    r.email_sent_at, r.email_status, r.email_error,
                    r.created_at, r.updated_at,
                ),
            )

    def get(self, announcement_id: str, user_id: str) -> AnnouncementRead | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM announcement_reads
                WHERE announcement_id = %s AND user_id = %s
                """,
                (announcement_id, user_id),
            ).fetchone()
        return self._map_row(row)

    def list_for_announcement(self, announcement_id: str) -> list[AnnouncementRead]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM announcement_reads
                WHERE announcement_id = %s
                ORDER BY created_at ASC
                """,
                (announcement_id,),
            ).fetchall()
        return [self._map_row(row) for row in rows]

    def list_for_user(self, user_id: str) -> list[AnnouncementRead]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM announcement_reads
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [self._map_row(row) for row in rows]

    def count_stats(self, announcement_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_reads,
                    COUNT(opened_at) AS opened,
                    COUNT(read_at) AS read,
                    COUNT(acknowledged_at) AS acknowledged,
                    COUNT(CASE WHEN email_status = 'sent' THEN 1 END) AS email_sent,
                    COUNT(CASE WHEN email_status = 'failed' THEN 1 END) AS email_failed
                FROM announcement_reads
                WHERE announcement_id = %s
                """,
                (announcement_id,),
            ).fetchone()
        return {
            "total_reads": int(row["total_reads"]) if row else 0,
            "opened": int(row["opened"]) if row else 0,
            "read": int(row["read"]) if row else 0,
            "acknowledged": int(row["acknowledged"]) if row else 0,
            "email_sent": int(row["email_sent"]) if row else 0,
            "email_failed": int(row["email_failed"]) if row else 0,
        }

    def _map_row(self, row) -> AnnouncementRead | None:
        if row is None:
            return None
        return AnnouncementRead(
            id=row["id"],
            announcement_id=row["announcement_id"],
            user_id=row["user_id"],
            opened_at=row["opened_at"],
            read_at=row["read_at"],
            acknowledged_at=row["acknowledged_at"],
            email_sent_at=row["email_sent_at"],
            email_status=row["email_status"],
            email_error=row["email_error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
