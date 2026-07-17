from backend.models.notification_event import NotificationEvent
from backend.utils.time import utc_now_iso

now = utc_now_iso

class PostgresNotificationEventRepository:
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
            with conn.cursor() as cur:
                cur.execute(
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_events
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (event_id, user_id),
                )
                row = cur.fetchone()

        return self._row_to_event(row) if row else None

    def list_for_user(self, user_id: str, limit: int = 50) -> list[NotificationEvent]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_events
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (user_id, int(limit)),
                )
                rows = cur.fetchall()

        return [self._row_to_event(row) for row in rows]

    def list_pending_due(self, now: str, limit: int = 50) -> list[NotificationEvent]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM notification_events
                    WHERE status IN ('pending', 'retrying')
                      AND (next_retry_at IS NULL OR next_retry_at <= %s)
                    ORDER BY created_at ASC
                    LIMIT %s
                    """,
                    (now, int(limit)),
                )
                rows = cur.fetchall()

        return [self._row_to_event(row) for row in rows]

    def list_pending_due_for_user(self, user_id: str, now: str, limit: int = 50) -> list[NotificationEvent]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT * FROM notification_events
                       WHERE user_id = %s AND status IN ('pending', 'retrying')
                         AND (next_retry_at IS NULL OR next_retry_at <= %s)
                       ORDER BY created_at ASC LIMIT %s""",
                    (user_id, now, int(limit)),
                )
                rows = cur.fetchall()
        return [self._row_to_event(row) for row in rows]

    def claim_for_dispatch(self, event_id: str, claimed_at: str, stale_before: str) -> bool:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE notification_events SET status = 'processing', updated_at = %s
                       WHERE id = %s AND (
                         status IN ('pending', 'retrying')
                         OR (status = 'processing' AND updated_at <= %s)
                       )""",
                    (claimed_at, event_id, stale_before),
                )
                claimed = cur.rowcount == 1
            conn.commit()
            return claimed

    def mark_sent(self, event_id: str, sent_at: str) -> None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE notification_events
                    SET
                        status = 'sent',
                        sent_at = %s,
                        updated_at = %s,
                        last_error = NULL
                    WHERE id = %s
                    """,
                    (sent_at, sent_at, event_id),
                )
            conn.commit()

    def increment_attempt(self, event_id: str, error: str, updated_at: str, next_retry_at: str | None) -> None:
        status = "retrying" if next_retry_at else "failed"

        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE notification_events
                    SET
                        attempts = attempts + 1,
                        status = %s,
                        last_error = %s,
                        next_retry_at = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (status, error, next_retry_at, updated_at, event_id),
                )
            conn.commit()
    def mark_retrying(self, event_id: str, last_error: str, next_retry_at: str) -> None:
        now_value = now()

        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE notification_events
                    SET
                        status = %s,
                        attempts = attempts + 1,
                        last_error = %s,
                        next_retry_at = %s,
                        updated_at = %s
                    WHERE id = %s
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
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE notification_events
                    SET
                        status = %s,
                        attempts = attempts + 1,
                        last_error = %s,
                        updated_at = %s
                    WHERE id = %s
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
            query += " WHERE status = %s"
            params.append(status)

        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

        return [self._row_to_event(row) for row in rows]
