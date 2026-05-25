#!/usr/bin/env python3
"""
Unit tests for destination error normalization.

Run from project root:
    python -m unittest backend.services_v2.job_support.test_destination_error
    # or directly:
    python backend/services_v2/job_support/test_destination_error.py
"""
import json
import os
import sys
import unittest

# Ensure project root is on sys.path when running the file directly.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../..")
)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.job import Job  # noqa: E402
from backend.services_v2.job_support.destination_error import (  # noqa: E402
    _classify_exception,
    apply_destination_failure,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_job(status: str = "completed") -> Job:
    return Job(
        id="test-job-id",
        user_id="u1",
        source_type="direct",
        source_value="https://example.com/file.zip",
        status=status,
        provider_config_id=None,
        provider_name=None,
        provider_profile_name=None,
        provider_resource_id=None,
        provider_status=None,
        provider_payload_json=None,
        destination_config_id=None,
        destination_name="synology",
        destination_profile_name=None,
        output_mode=None,
        output_links_json="[]",
        unrestricted_at=None,
        error_message=None,
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-01T00:00:00Z",
        started_at=None,
        completed_at=None,
    )


# ---------------------------------------------------------------------------
# _classify_exception
# ---------------------------------------------------------------------------

class TestClassifyException(unittest.TestCase):

    def test_connection_refused(self):
        exc = Exception(
            "HTTPConnectionPool(host='192.168.1.10', port=5000): "
            "Max retries exceeded — Caused by NewConnectionError: Connection refused"
        )
        key, params, label = _classify_exception(exc)
        self.assertEqual(key, "destination.message.connection_refused")
        self.assertEqual(params, {})
        self.assertNotIn("HTTPConnectionPool", label)

    def test_timeout_variants(self):
        for msg in [
            "Read timed out after 30s",
            "Connection timeout exceeded",
            "Request timed out (30s)",
        ]:
            with self.subTest(msg=msg):
                key, params, _ = _classify_exception(Exception(msg))
                self.assertEqual(key, "destination.message.timeout")
                self.assertEqual(params, {})

    def test_auth_failed_variants(self):
        for msg in [
            "DSM auth failed: invalid user",
            "Authentication error: wrong password",
            "auth token rejected",
        ]:
            with self.subTest(msg=msg):
                key, params, _ = _classify_exception(Exception(msg))
                self.assertEqual(key, "destination.message.auth_failed")
                self.assertEqual(params, {})

    def test_generic_fallback_includes_reason(self):
        exc = ValueError("Unexpected server response: 503 Service Unavailable")
        key, params, label = _classify_exception(exc)
        self.assertEqual(key, "destination.message.failed")
        self.assertIn("reason", params)
        self.assertIn("503", params["reason"])

    def test_fallback_truncates_long_message(self):
        exc = Exception("E" * 300)
        _, params, _ = _classify_exception(exc)
        self.assertLessEqual(len(params.get("reason", "")), 125)

    def test_fallback_keeps_first_line_only(self):
        exc = Exception("First line summary\nDetailed traceback line 2\nLine 3")
        _, params, _ = _classify_exception(exc)
        self.assertNotIn("Line 3", params.get("reason", ""))
        self.assertNotIn("traceback", params.get("reason", "").lower())

    def test_connection_refused_label_is_clean(self):
        exc = Exception("HTTPConnectionPool: Max retries — Connection refused")
        _, _, label = _classify_exception(exc)
        self.assertNotIn("HTTPConnectionPool", label)


# ---------------------------------------------------------------------------
# apply_destination_failure — usable job statuses (no error_message pollution)
# ---------------------------------------------------------------------------

class TestApplyDestinationFailureUsableStatuses(unittest.TestCase):
    """
    For ready / partially_ready / completed jobs, error_message must NOT be
    set — the job is still usable and the failure is destination-only.
    """

    def _run(self, status: str, exc_msg: str):
        job = _make_job(status=status)
        apply_destination_failure(job, Exception(exc_msg))
        return job

    def test_completed_no_error_message(self):
        job = self._run("completed", "HTTPConnectionPool: Connection refused")
        self.assertIsNone(job.error_message,
            "error_message must be None for a completed job with destination failure")

    def test_ready_no_error_message(self):
        job = self._run("ready", "Read timed out after 30 seconds")
        self.assertIsNone(job.error_message)

    def test_partially_ready_no_error_message(self):
        job = self._run("partially_ready", "Connection refused")
        self.assertIsNone(job.error_message)

    def test_completed_no_httpconnectionpool_in_destination_message(self):
        job = self._run("completed", "HTTPConnectionPool: Max retries — Connection refused")
        self.assertNotIn("HTTPConnectionPool", str(job.destination_message or ""))

    def test_last_message_source_is_null_for_usable_jobs(self):
        """
        The API serialization sets last_message = job.error_message.
        Verify error_message is None so last_message will also be None.
        """
        job = self._run("completed", "HTTPConnectionPool: Max retries exceeded")
        # error_message is the source for last_message in serialization
        self.assertIsNone(job.error_message,
            "last_message (= error_message) must be None for a completed job")


# ---------------------------------------------------------------------------
# apply_destination_failure — non-usable statuses (error_message IS set)
# ---------------------------------------------------------------------------

class TestApplyDestinationFailureNonUsableStatuses(unittest.TestCase):

    def test_failed_job_sets_error_message(self):
        job = _make_job(status="failed")
        apply_destination_failure(job, Exception("Provider unreachable"))
        self.assertIsNotNone(job.error_message)

    def test_created_job_sets_error_message(self):
        job = _make_job(status="created")
        apply_destination_failure(job, Exception("Some error"))
        self.assertIsNotNone(job.error_message)

    def test_downloading_job_sets_error_message(self):
        for status in ("queued", "downloading", "started"):
            with self.subTest(status=status):
                job = _make_job(status=status)
                apply_destination_failure(job, Exception("Some error"))
                self.assertIsNotNone(job.error_message)


# ---------------------------------------------------------------------------
# apply_destination_failure — fields always set
# ---------------------------------------------------------------------------

class TestApplyDestinationFailureFields(unittest.TestCase):

    def test_destination_status_always_failed(self):
        job = _make_job(status="completed")
        apply_destination_failure(job, Exception("any"))
        self.assertEqual(job.destination_status, "failed")

    def test_message_key_always_set(self):
        for exc_msg in [
            "Connection refused",
            "Request timed out",
            "DSM auth failed",
            "Some unknown error",
        ]:
            with self.subTest(exc=exc_msg):
                job = _make_job(status="completed")
                apply_destination_failure(job, Exception(exc_msg))
                self.assertIsNotNone(job.destination_message_key)

    def test_connection_refused_key(self):
        job = _make_job(status="completed")
        apply_destination_failure(job, Exception("HTTPConnectionPool: Connection refused"))
        self.assertEqual(job.destination_message_key, "destination.message.connection_refused")
        self.assertIsNone(job.destination_message_params)

    def test_timeout_key(self):
        job = _make_job(status="ready")
        apply_destination_failure(job, Exception("Connection timeout"))
        self.assertEqual(job.destination_message_key, "destination.message.timeout")
        self.assertIsNone(job.destination_message_params)

    def test_auth_key(self):
        job = _make_job(status="completed")
        apply_destination_failure(job, Exception("DSM auth failed"))
        self.assertEqual(job.destination_message_key, "destination.message.auth_failed")
        self.assertIsNone(job.destination_message_params)

    def test_fallback_key_with_params(self):
        job = _make_job(status="completed")
        apply_destination_failure(job, ValueError("Server error 503"))
        self.assertEqual(job.destination_message_key, "destination.message.failed")
        params = json.loads(job.destination_message_params)
        self.assertIn("reason", params)
        self.assertIn("503", params["reason"])

    def test_destination_last_attempt_updated(self):
        job = _make_job(status="completed")
        job.destination_last_attempt = "2020-01-01T00:00:00Z"
        apply_destination_failure(job, Exception("Connection refused"))
        self.assertNotEqual(job.destination_last_attempt, "2020-01-01T00:00:00Z")
        self.assertIsNotNone(job.destination_last_attempt)

    def test_updated_at_set(self):
        job = _make_job(status="completed")
        old_updated = job.updated_at
        apply_destination_failure(job, Exception("Connection refused"))
        self.assertNotEqual(job.updated_at, old_updated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
