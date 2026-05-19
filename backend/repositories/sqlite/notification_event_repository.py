from backend.models.notification_event import NotificationEvent
from backend.utils.time import utc_now_iso

now = utc_now_iso

class SQLiteNotificationEventRepository:
    def __init__(self, db):
        self.db = db

    def _row_to_event(self, row) -> NotificationEvent:
        return NotificationEvent(
            id=row["id"],
            user_id=row["user_id"],
            job_id=row["job_id"],
            type=row["type"],
            severity=row["severity"],
            title=row["title"],
            message=row["message"],
            payload_json=row["payload_json"],
            status=row["status"],
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            last_error=row["last_error"],
            triggered_by_rule_ids_json=row["triggered_by_rule_ids_json"],
            triggered_by_config_ids_json=row["triggered_by_config_ids_json"],
            next_retry_at=row["next_retry_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            sent_at=row["sent_at"],
        )

    def create(self, event: NotificationEvent) -> NotificationEvent:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO notification_events (
                    id,
                    user_id,
                    job_id,
                    type,
                    severity,
                    title,
                    message,
                    payload_json,
                    status,
                    attempts,
                    max_attempts,
                    last_error,
                    triggered_by_rule_ids_json,
                    triggered_by_config_ids_json,
                    next_retry_at,
                    created_at,
                    updated_at,
                    sent_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.user_id,
                    event.job_id,
                    event.type,
                    event.severity,
                    event.title,
                    event.message,
                    event.payload_json,
                    event.status,
                    event.attempts,
                    event.max_attempts,
                    event.last_error,
                    event.triggered_by_rule_ids_json,
                    event.triggered_by_config_ids_json,
                    event.next_retry_at,
                    event.created_at,
                    event.updated_at,
                    event.sent_at,
                ),
            )
            conn.commit()

        return event

    def get_by_id(self, user_id: str, event_id: str) -> NotificationEvent | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM notification_events
                WHERE id = ?
                  AND user_id = ?
                """,
                (event_id, user_id),
            ).fetchone()

        return self._row_to_event(row) if row else None

    def list_for_user(self, user_id: str, limit: int = 50) -> list[NotificationEvent]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM notification_events
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (user_id, int(limit)),
            ).fetchall()

        return [self._row_to_event(row) for row in rows]

    def list_pending_due(self, now: str, limit: int = 50) -> list[NotificationEvent]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM notification_events
                WHERE status IN ('pending', 'retrying')
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (now, int(limit)),
            ).fetchall()

        return [self._row_to_event(row) for row in rows]

    def mark_sent(self, event_id: str, sent_at: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE notification_events
                SET
                    status = 'sent',
                    sent_at = ?,
                    updated_at = ?,
                    last_error = NULL
                WHERE id = ?
                """,
                (sent_at, sent_at, event_id),
            )
            conn.commit()

    def increment_attempt(self, event_id: str, error: str, updated_at: str, next_retry_at: str | None) -> None:
        status = "retrying" if next_retry_at else "failed"

        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE notification_events
                SET
                    attempts = attempts + 1,
                    status = ?,
                    last_error = ?,
                    next_retry_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (status, error, next_retry_at, updated_at, event_id),
            )
            conn.commit()
    def mark_retrying(self, event_id: str, last_error: str, next_retry_at: str) -> None:
        now_value = now()

        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE notification_events
                SET
                    status = ?,
                    attempts = attempts + 1,
                    last_error = ?,
                    next_retry_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    "retrying",
                    last_error,
                    next_retry_at,
                    now_value,
                    event_id,
                ),
            )
            conn.commit()

    def mark_failed(self, event_id: str, last_error: str) -> None:
        now_value = now()

        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE notification_events
                SET
                    status = ?,
                    attempts = attempts + 1,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    "failed",
                    last_error,
                    now_value,
                    event_id,
                ),
            )
            conn.commit()

    def list_all(self, limit: int = 100, status: str | None = None) -> list[NotificationEvent]:
        limit = max(1, min(int(limit), 500))

        query = "SELECT * FROM notification_events"
        params = []

        if status:
            query += " WHERE status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.db.connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_event(row) for row in rows]