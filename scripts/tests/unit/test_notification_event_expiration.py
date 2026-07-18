#!/usr/bin/env python3
import os
import sys
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.notification_event import NotificationEvent
from backend.repositories.postgres.notification_event_repository import PostgresNotificationEventRepository
from backend.repositories.sqlite.notification_event_repository import SQLiteNotificationEventRepository
from backend.services_v2.notification_dispatcher_service import NotificationDispatcherService
from backend.services_v2.notification_dispatcher_support.event_dispatch import mark_event_failure
from backend.services_v2.notification_dispatcher_support.runner import run_once_for_user
from backend.storage.db import Database


NOW_DT = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
NOW = NOW_DT.isoformat()
USER_ID = "notification-expiration-user"
EXPIRED_REASON = "Notification event expired before dispatch: age exceeds configured maximum"


class NotificationExpirationSQLiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "notifications.sqlite3"))
        self.db.init_schema(os.path.join(_PROJECT_ROOT, "backend/storage/schema.sql"))
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO users (id, email, created_at, updated_at)
                   VALUES (?, ?, ?, ?)""",
                (USER_ID, "notifications@example.test", NOW, NOW),
            )
            conn.commit()
        self.repo = SQLiteNotificationEventRepository(self.db)
        self.sent = []

    def tearDown(self):
        self.tmp.cleanup()

    def create_event(self, event_id, *, age_hours=1, status="pending", attempts=0, max_attempts=5):
        created_at = (NOW_DT - timedelta(hours=age_hours)).isoformat()
        next_retry_at = NOW if status == "retrying" else None
        event = NotificationEvent(
            id=event_id,
            user_id=USER_ID,
            job_id="job-regression",
            type="provider.status.changed",
            severity="info",
            title="Provider status",
            message="Non-sensitive test message",
            payload_json="{}",
            status=status,
            attempts=attempts,
            max_attempts=max_attempts,
            last_error="previous failure" if status == "retrying" else None,
            triggered_by_rule_ids_json='["rule-1"]',
            triggered_by_config_ids_json='["config-1"]',
            next_retry_at=next_retry_at,
            created_at=created_at,
            updated_at=created_at,
            sent_at=created_at if status == "sent" else None,
        )
        self.repo.create(event)
        return event

    def run_dispatcher(self):
        def dispatch(_user_id, event):
            self.sent.append(event.id)
            self.repo.mark_sent(event.id, NOW)
            return "sent"

        return run_once_for_user(
            USER_ID,
            25,
            self.repo,
            dispatch,
            lambda event, exc: mark_event_failure(event, exc, self.repo, 3),
            lambda: NOW,
            24,
        )

    def get(self, event_id):
        return self.repo.get_by_id(USER_ID, event_id)

    def test_recent_pending_event_is_sent_normally(self):
        self.create_event("recent-pending")
        result = self.run_dispatcher()
        self.assertEqual(["recent-pending"], self.sent)
        self.assertEqual("sent", self.get("recent-pending").status)
        self.assertEqual(1, result["sent"])

    def test_recent_retrying_event_below_max_attempts_is_sent(self):
        self.create_event("recent-retrying", status="retrying", attempts=2)
        self.run_dispatcher()
        self.assertEqual(["recent-retrying"], self.sent)

    def test_old_pending_event_is_expired_without_send(self):
        self.create_event("old-pending", age_hours=25)
        self.run_dispatcher()
        event = self.get("old-pending")
        self.assertEqual("expired", event.status)
        self.assertEqual(EXPIRED_REASON, event.last_error)
        self.assertIsNone(event.next_retry_at)
        self.assertEqual([], self.sent)

    def test_old_retrying_event_is_expired_without_send(self):
        self.create_event("old-retrying", age_hours=25, status="retrying", attempts=2)
        self.run_dispatcher()
        self.assertEqual("expired", self.get("old-retrying").status)
        self.assertEqual([], self.sent)

    def test_old_event_with_zero_attempts_is_not_sent(self):
        self.create_event("old-zero", age_hours=24 * 29, attempts=0)
        self.run_dispatcher()
        self.assertEqual("expired", self.get("old-zero").status)
        self.assertEqual([], self.sent)

    def test_recent_event_at_max_attempts_becomes_failed(self):
        self.create_event("exhausted", attempts=5, max_attempts=5)
        self.run_dispatcher()
        event = self.get("exhausted")
        self.assertEqual("failed", event.status)
        self.assertIsNone(event.next_retry_at)
        self.assertEqual([], self.sent)

    def test_old_terminal_events_remain_unchanged(self):
        for status in ("sent", "failed", "ignored"):
            self.create_event(f"terminal-{status}", age_hours=24 * 29, status=status)
        self.run_dispatcher()
        for status in ("sent", "failed", "ignored"):
            self.assertEqual(status, self.get(f"terminal-{status}").status)

    def test_startup_cleanup_is_idempotent(self):
        self.create_event("startup-old", age_hours=24 * 29, status="retrying", attempts=2)
        service = NotificationDispatcherService(None, self.repo, None, None, max_age_hours=24)
        with patch("backend.services_v2.notification_dispatcher_service.now", return_value=NOW):
            self.assertEqual(1, service.cleanup_stale_events_on_startup())
            self.assertEqual(0, service.cleanup_stale_events_on_startup())
        self.assertEqual("expired", self.get("startup-old").status)

    def test_concurrent_startup_cleanup_counts_rows_once(self):
        self.create_event("startup-concurrent", age_hours=24 * 29)
        barrier = threading.Barrier(2)
        counts = []
        lock = threading.Lock()

        def cleanup():
            service = NotificationDispatcherService(None, self.repo, None, None, max_age_hours=24)
            barrier.wait()
            with patch("backend.services_v2.notification_dispatcher_service.now", return_value=NOW):
                count = service.cleanup_stale_events_on_startup()
            with lock:
                counts.append(count)

        threads = [threading.Thread(target=cleanup) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([0, 1], sorted(counts))

    def test_stale_processing_lease_is_expired(self):
        self.create_event("crashed-processing", age_hours=24 * 29, status="processing")
        self.run_dispatcher()
        self.assertEqual("expired", self.get("crashed-processing").status)
        self.assertEqual([], self.sent)

    def test_two_dispatchers_cannot_send_expired_event(self):
        self.create_event("concurrent-old", age_hours=24 * 29, attempts=2)
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            self.run_dispatcher()

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], self.sent)
        self.assertEqual("expired", self.get("concurrent-old").status)

    def test_atomic_claim_is_preserved_for_recent_event(self):
        self.create_event("concurrent-recent")
        cutoff = (NOW_DT - timedelta(hours=24)).isoformat()
        stale = (NOW_DT - timedelta(minutes=10)).isoformat()
        claims = []

        def claim():
            claims.append(self.repo.claim_for_dispatch("concurrent-recent", NOW, stale, cutoff))

        threads = [threading.Thread(target=claim) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([False, True], sorted(claims))

    def test_failure_at_last_attempt_clears_retry_timestamp(self):
        event = self.create_event("last-attempt", status="retrying", attempts=4, max_attempts=5)
        mark_event_failure(event, RuntimeError("delivery failed"), self.repo, 3)
        failed = self.get("last-attempt")
        self.assertEqual(5, failed.attempts)
        self.assertEqual("failed", failed.status)
        self.assertIsNone(failed.next_retry_at)


class FakeCursor:
    def __init__(self):
        self.calls = []
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params):
        self.calls.append((" ".join(sql.split()), params))

    def fetchall(self):
        return []


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self._cursor

    def commit(self):
        pass


class FakePostgresDb:
    def __init__(self):
        self.cursor = FakeCursor()

    def connect(self):
        return FakeConnection(self.cursor)


class NotificationExpirationPostgresQueryTests(unittest.TestCase):
    def test_postgres_cleanup_and_selection_use_ttl_and_attempt_guards(self):
        db = FakePostgresDb()
        repo = PostgresNotificationEventRepository(db)
        cutoff = (NOW_DT - timedelta(hours=24)).isoformat()
        stale = (NOW_DT - timedelta(minutes=10)).isoformat()
        self.assertEqual(1, repo.expire_stale(cutoff, NOW, stale))
        repo.list_pending_due_for_user(USER_ID, NOW, cutoff, stale, 25)
        cleanup_sql = db.cursor.calls[0][0]
        selection_sql = db.cursor.calls[1][0]
        self.assertIn("created_at < %s", cleanup_sql)
        self.assertIn("status = 'processing' AND updated_at <= %s", cleanup_sql)
        self.assertIn("created_at >= %s", selection_sql)
        self.assertIn("attempts < max_attempts", selection_sql)
        self.assertIn("status = 'processing' AND updated_at <= %s", selection_sql)


if __name__ == "__main__":
    unittest.main(verbosity=2)
