#!/usr/bin/env python3
"""
Unit tests for safe_destination_error_message / classify_destination_error_message.

Run from project root:
    source .venv/bin/activate
    python scripts/tests/unit/test_safe_destination_error_message.py
"""

import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services_v2.job_support.destination_failure import (
    classify_destination_error_message,
    safe_destination_error_message,
    is_destination_client_error,
    DESTINATION_ERROR_STATUS,
)
from backend.services_v2.destinations.synology_destination import (
    SynologyDestinationError,
    SynologyDestination,
)

import requests.exceptions

AUTH_MSG       = "Destination authentication failed. Please check the destination credentials."
ROOT_MSG       = "Destination folder does not exist or is not accessible. Please check the destination folder."
FOLDER_MSG     = "Destination write access failed. Please check folder permissions and destination path."
TEMP_MSG       = "Destination temporarily unavailable. Please retry later."
GENERIC_MSG    = "Destination error. Please check the destination configuration."
SSL_MSG        = "Destination SSL certificate error. Please check the SSL configuration."
CONN_ERR_MSG   = "Destination connection error. Please check the URL and network access."


class TestClassifyDestinationErrorMessage(unittest.TestCase):

    # ── SynologyDestinationError — auth ────────────────────────────────────────

    def test_synology_login_failed(self):
        exc = SynologyDestinationError("NAS DownloadStation login failed (code=401)")
        self.assertEqual(classify_destination_error_message(exc), AUTH_MSG)

    def test_synology_filestation_login_failed(self):
        exc = SynologyDestinationError("NAS FileStation login failed (code=402)")
        self.assertEqual(classify_destination_error_message(exc), AUTH_MSG)

    def test_synology_sid_missing(self):
        # SID missing — treated as generic, not auth
        exc = SynologyDestinationError("NAS DownloadStation login succeeded but SID is missing")
        self.assertEqual(classify_destination_error_message(exc), GENERIC_MSG)

    # ── SynologyDestinationError — folder/path ─────────────────────────────────

    def test_synology_folder_creation_http_error(self):
        exc = SynologyDestinationError("NAS folder creation HTTP error parent=/downloads name=show: Connection refused")
        self.assertEqual(classify_destination_error_message(exc), FOLDER_MSG)

    def test_synology_folder_creation_failed(self):
        exc = SynologyDestinationError("NAS folder creation failed code=414 parent=/downloads name=show data={}")
        self.assertEqual(classify_destination_error_message(exc), FOLDER_MSG)

    def test_synology_folder_creation_invalid_json(self):
        exc = SynologyDestinationError("NAS folder creation returned invalid JSON parent=/downloads name=show")
        self.assertEqual(classify_destination_error_message(exc), FOLDER_MSG)

    # ── SynologyDestinationError — generic ─────────────────────────────────────

    def test_synology_task_creation_failed(self):
        exc = SynologyDestinationError("NAS task creation failed code=101 destination=downloads")
        self.assertEqual(classify_destination_error_message(exc), GENERIC_MSG)

    def test_synology_test_failed(self):
        exc = SynologyDestinationError("NAS Download Station test failed (code=119)")
        self.assertEqual(classify_destination_error_message(exc), GENERIC_MSG)

    def test_synology_no_task_created(self):
        exc = SynologyDestinationError("No NAS task created")
        self.assertEqual(classify_destination_error_message(exc), GENERIC_MSG)

    # ── requests exceptions ─────────────────────────────────────────────────────

    def test_requests_connection_error(self):
        exc = requests.exceptions.ConnectionError("Connection refused")
        self.assertEqual(classify_destination_error_message(exc), TEMP_MSG)

    def test_requests_timeout(self):
        exc = requests.exceptions.Timeout("Read timed out")
        self.assertEqual(classify_destination_error_message(exc), TEMP_MSG)

    def test_requests_ssl_error(self):
        exc = requests.exceptions.SSLError("SSL certificate verify failed")
        self.assertEqual(classify_destination_error_message(exc), SSL_MSG)

    def test_requests_generic(self):
        exc = requests.exceptions.RequestException("Some network error")
        self.assertEqual(classify_destination_error_message(exc), CONN_ERR_MSG)

    # ── PermissionError ─────────────────────────────────────────────────────────

    def test_permission_error(self):
        exc = PermissionError("Permission denied: /data/downloads")
        self.assertEqual(classify_destination_error_message(exc), FOLDER_MSG)

    # ── Non-destination exception ───────────────────────────────────────────────

    def test_generic_exception(self):
        exc = RuntimeError("Something unexpected")
        self.assertEqual(classify_destination_error_message(exc), GENERIC_MSG)

    # ── is_destination_client_error ─────────────────────────────────────────────

    def test_synology_is_client_error(self):
        self.assertTrue(is_destination_client_error(SynologyDestinationError("login failed")))

    def test_connection_error_is_client_error(self):
        self.assertTrue(is_destination_client_error(requests.exceptions.ConnectionError()))

    def test_timeout_is_client_error(self):
        self.assertTrue(is_destination_client_error(requests.exceptions.Timeout()))

    def test_permission_error_is_client_error(self):
        self.assertTrue(is_destination_client_error(PermissionError()))

    def test_runtime_error_not_client_error(self):
        self.assertFalse(is_destination_client_error(RuntimeError("boom")))

    def test_value_error_not_client_error(self):
        self.assertFalse(is_destination_client_error(ValueError("bad")))

    # ── No raw message leaks ────────────────────────────────────────────────────

    def test_no_raw_synology_code_in_output(self):
        """safe_destination_error_message must never return the raw NAS error string."""
        exc = SynologyDestinationError("NAS DownloadStation login failed (code=401)")
        result = safe_destination_error_message(exc)
        self.assertNotIn("code=401", result)
        self.assertNotIn("NAS DownloadStation", result)

    def test_no_raw_path_in_output(self):
        exc = SynologyDestinationError("NAS folder creation failed code=414 parent=/downloads name=show data={}")
        result = safe_destination_error_message(exc)
        self.assertNotIn("/downloads", result)
        self.assertNotIn("code=414", result)

    # ── Destination root not accessible ────────────────────────────────────────

    def test_root_not_accessible_code(self):
        exc = SynologyDestinationError("NAS destination root not accessible root=rfrfrfef code=408")
        self.assertEqual(classify_destination_error_message(exc), ROOT_MSG)

    def test_root_not_accessible_invalid_json(self):
        exc = SynologyDestinationError("NAS destination root not accessible root=rfrfrfef invalid JSON")
        self.assertEqual(classify_destination_error_message(exc), ROOT_MSG)

    def test_root_not_accessible_http_error(self):
        exc = SynologyDestinationError("NAS destination root not accessible root=downloads http error: Connection refused")
        self.assertEqual(classify_destination_error_message(exc), ROOT_MSG)

    def test_root_error_does_not_leak_path(self):
        exc = SynologyDestinationError("NAS destination root not accessible root=secret_share code=408")
        result = safe_destination_error_message(exc)
        self.assertNotIn("secret_share", result)
        self.assertNotIn("code=408", result)
        self.assertEqual(result, ROOT_MSG)

    # ── _extract_destination_root parsing ──────────────────────────────────────

    def _make_dest(self, base: str | None) -> SynologyDestination:
        return SynologyDestination(
            synology_url="http://nas.local:5000",
            username="admin",
            password="pw",
            destination_base=base or "",
        )

    def test_extract_root_simple(self):
        self.assertEqual(self._make_dest("downloads")._extract_destination_root(), "downloads")

    def test_extract_root_with_subfolder(self):
        self.assertEqual(self._make_dest("downloads/XXXXXXX")._extract_destination_root(), "downloads")

    def test_extract_root_with_leading_slash(self):
        self.assertEqual(self._make_dest("/downloads/series")._extract_destination_root(), "downloads")

    def test_extract_root_trailing_slash(self):
        self.assertEqual(self._make_dest("downloads/")._extract_destination_root(), "downloads")

    def test_extract_root_empty(self):
        self.assertIsNone(self._make_dest("")._extract_destination_root())

    def test_extract_root_only_slashes(self):
        self.assertIsNone(self._make_dest("///")._extract_destination_root())

    def test_extract_root_none_equivalent(self):
        dest = SynologyDestination(
            synology_url="http://nas.local:5000",
            username="admin",
            password="pw",
            destination_base=None,
        )
        self.assertIsNone(dest._extract_destination_root())

    # ── DESTINATION_ERROR_STATUS ────────────────────────────────────────────────

    def test_error_status_is_422(self):
        self.assertEqual(DESTINATION_ERROR_STATUS, 422)


if __name__ == "__main__":
    unittest.main(verbosity=2)
