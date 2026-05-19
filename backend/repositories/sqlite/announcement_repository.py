from backend.utils.time import utc_now_iso

from backend.models.announcement import Announcement

_now = utc_now_iso


class AnnouncementRepository:
    def __init__(self, db):
        self.db = db

    def create(self, a: Announcement) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO announcements (
                    id, title, body, type, severity,
                    is_active, show_as_banner, require_acknowledgement,
                    track_open, send_email,
                    starts_at, ends_at, deleted_at, created_by_user_id,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    a.id, a.title, a.body, a.type, a.severity,
                    1 if a.is_active else 0,
                    1 if a.show_as_banner else 0,
                    1 if a.require_acknowledgement else 0,
                    1 if a.track_open else 0,
                    1 if a.send_email else 0,
                    a.starts_at, a.ends_at, a.deleted_at, a.created_by_user_id,
                    a.created_at, a.updated_at,
                ),
            )

    def get_by_id(self, announcement_id: str) -> Announcement | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM announcements WHERE id = ?",
                (announcement_id,),
            ).fetchone()
        return self._map_row(row)

    def list_all(self) -> list[Announcement]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM announcements
                WHERE deleted_at IS NULL
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [self._map_row(row) for row in rows]

    def list_active(self, now: str) -> list[Announcement]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM announcements
                WHERE is_active = 1
                  AND deleted_at IS NULL
                  AND (starts_at IS NULL OR starts_at <= ?)
                  AND (ends_at IS NULL OR ends_at >= ?)
                ORDER BY created_at DESC
                """,
                (now, now),
            ).fetchall()
        return [self._map_row(row) for row in rows]

    def update(self, a: Announcement) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE announcements
                SET title = ?, body = ?, type = ?, severity = ?,
                    is_active = ?, show_as_banner = ?, require_acknowledgement = ?,
                    track_open = ?, send_email = ?,
                    starts_at = ?, ends_at = ?, deleted_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    a.title, a.body, a.type, a.severity,
                    1 if a.is_active else 0,
                    1 if a.show_as_banner else 0,
                    1 if a.require_acknowledgement else 0,
                    1 if a.track_open else 0,
                    1 if a.send_email else 0,
                    a.starts_at, a.ends_at, a.deleted_at,
                    a.updated_at, a.id,
                ),
            )

    def delete(self, announcement_id: str) -> None:
        now = _now()
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE announcements
                SET deleted_at = ?, is_active = 0, updated_at = ?
                WHERE id = ?
                """,
                (now, now, announcement_id),
            )

    def _map_row(self, row) -> Announcement | None:
        if row is None:
            return None
        return Announcement(
            id=row["id"],
            title=row["title"],
            body=row["body"],
            type=row["type"],
            severity=row["severity"],
            is_active=bool(row["is_active"]),
            show_as_banner=bool(row["show_as_banner"]),
            require_acknowledgement=bool(row["require_acknowledgement"]),
            track_open=bool(row["track_open"]),
            send_email=bool(row["send_email"]),
            starts_at=row["starts_at"],
            ends_at=row["ends_at"],
            deleted_at=row["deleted_at"],
            created_by_user_id=row["created_by_user_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
