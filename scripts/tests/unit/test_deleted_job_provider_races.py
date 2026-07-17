import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

from backend.models.job import Job
from backend.repositories.sqlite.job_repository import JobRepository
from backend.repositories.sqlite.notification_event_repository import SQLiteNotificationEventRepository
from backend.services_v2.job_service import JobService
from backend.services_v2.providers.alldebrid_client import AllDebridApiError, AllDebridClientError
from backend.services_v2.user_context import UserContext
from backend.storage.db import Database


NOW = "2026-07-17T12:00:00+00:00"


def make_job(job_id="job-1", status="downloading"):
    return Job(
        id=job_id, user_id="user-1", source_type="magnet", source_value="magnet:?xt=test",
        status=status, provider_config_id="provider-1", provider_name="alldebrid",
        provider_profile_name="AllDebrid", provider_resource_id="magnet-1",
        provider_status=status, provider_payload_json="{}", destination_config_id=None,
        destination_name=None, destination_profile_name=None, output_mode=None,
        output_links_json=None, unrestricted_at=None, error_message=None,
        created_at=NOW, updated_at=NOW, started_at=NOW, completed_at=None,
    )


class NotificationRecorder:
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()

    def create_event(self, **payload):
        with self.lock:
            self.events.append(payload)
        return payload


class ProviderFactory:
    def __init__(self, provider):
        self.provider = provider

    def get_provider_for_user(self, **_kwargs):
        return self.provider


class DeletedJobProviderRaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / "test.db"))
        schema = Path(__file__).parents[3] / "backend/storage/schema.sql"
        self.db.init_schema(str(schema))
        self.db.run_column_migrations()
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO users (id,email,role,is_active,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                ("user-1", "user@example.test", "user", 1, NOW, NOW),
            )
        self.repo = JobRepository(self.db)
        self.notifications = NotificationRecorder()
        self.ctx = UserContext(user_id="user-1", role="user")

    def tearDown(self):
        self.tmp.cleanup()

    def service(self, provider):
        return JobService(
            self.repo, provider_factory=ProviderFactory(provider),
            notification_service=self.notifications,
        )

    def test_refresh_ignores_already_deleted_job(self):
        provider = Mock()
        self.assertIsNone(self.service(provider).refresh_job(self.ctx, "missing"))
        provider.get_torrent_info.assert_not_called()

    def test_file_selection_ignores_already_deleted_job(self):
        provider = Mock()
        self.assertIsNone(self.service(provider).select_files(self.ctx, "missing", "1"))
        provider.select_files.assert_not_called()

    def test_deleted_during_provider_call_emits_nothing_and_enqueues_nothing(self):
        self.repo.create(make_job())
        provider = Mock()
        provider.get_torrent_info.side_effect = lambda _id: (
            self.repo.delete("user-1", "job-1") or {"status": "downloaded"}
        )
        service = self.service(provider)
        service.unrestrict_job = Mock()
        self.assertIsNone(service.refresh_job(self.ctx, "job-1"))
        service.unrestrict_job.assert_not_called()
        self.assertEqual([], self.notifications.events)

    def test_deleted_during_failed_provider_call_emits_nothing(self):
        self.repo.create(make_job())
        provider = Mock()
        def fail(_id):
            self.repo.delete("user-1", "job-1")
            raise AllDebridApiError("AllDebrid API error: code=MAGNET_INVALID_ID message=invalid")
        provider.get_torrent_info.side_effect = fail
        self.assertIsNone(self.service(provider).refresh_job(self.ctx, "job-1"))
        self.assertEqual([], self.notifications.events)

    def test_magnet_invalid_id_is_terminal_and_not_scheduled_again(self):
        self.repo.create(make_job())
        provider = Mock()
        provider.get_torrent_info.side_effect = AllDebridApiError(
            "AllDebrid API error: code=MAGNET_INVALID_ID message=invalid"
        )
        result = self.service(provider).refresh_job(self.ctx, "job-1")
        self.assertEqual("failed", result.status)
        self.assertEqual("failed", result.provider_status)
        self.assertEqual([], self.repo.list_runnable_for_scheduler())
        self.assertEqual(1, len(self.notifications.events))

    def test_identical_temporary_failure_is_retryable_but_not_realerted(self):
        self.repo.create(make_job())
        provider = Mock()
        provider.get_torrent_info.side_effect = AllDebridClientError("AllDebrid timeout")
        service = self.service(provider)
        for _ in range(2):
            with self.assertRaises(AllDebridClientError):
                service.refresh_job(self.ctx, "job-1")
        self.assertEqual("downloading", self.repo.get_by_id("user-1", "job-1").status)
        self.assertEqual(1, len(self.notifications.events))

    def test_http_5xx_provider_failure_remains_retryable(self):
        self.repo.create(make_job())
        provider = Mock()
        provider.get_torrent_info.side_effect = AllDebridApiError("AllDebrid API error HTTP 503")
        with self.assertRaises(AllDebridApiError):
            self.service(provider).refresh_job(self.ctx, "job-1")
        self.assertEqual("downloading", self.repo.get_by_id("user-1", "job-1").status)

    def test_concurrent_failures_emit_once(self):
        self.repo.create(make_job())
        service = self.service(Mock())
        job = self.repo.get_by_id("user-1", "job-1")
        error = AllDebridApiError("AllDebrid API error: code=MAGNET_INVALID_ID message=invalid")
        threads = [threading.Thread(target=service._record_provider_failure, args=(self.ctx, job, error)) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, len(self.notifications.events))

    def test_deleting_one_job_does_not_affect_another(self):
        self.repo.create(make_job("job-1"))
        self.repo.create(make_job("job-2"))
        self.repo.delete("user-1", "job-1")
        self.assertEqual(["job-2"], [job.id for job in self.repo.list_runnable_for_scheduler()])

    def test_notification_event_can_only_be_claimed_by_one_dispatcher(self):
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO notification_events
                   (id,user_id,type,severity,title,message,status,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                ("event-1", "user-1", "provider.failed", "error", "failed", "failed", "pending", NOW, NOW),
            )
        repo = SQLiteNotificationEventRepository(self.db)
        claims = []
        lock = threading.Lock()
        def claim():
            value = repo.claim_for_dispatch("event-1", NOW, "2026-07-17T11:00:00+00:00")
            with lock:
                claims.append(value)
        threads = [threading.Thread(target=claim) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([False, True], sorted(claims))


if __name__ == "__main__":
    unittest.main()
