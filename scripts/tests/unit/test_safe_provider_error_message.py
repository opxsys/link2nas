#!/usr/bin/env python3
"""
Unit tests for safe_provider_error_message.

Run from project root:
    python scripts/tests/unit/test_safe_provider_error_message.py
"""

import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.routes_v2.jobs_support.errors import safe_provider_error_message
from backend.services_v2.providers.alldebrid_client import (
    AllDebridApiError,
    AllDebridAuthError,
    AllDebridClientError,
)
from backend.services_v2.providers.realdebrid_client import (
    RealDebridApiError,
    RealDebridAuthError,
    RealDebridClientError,
)

AUTH_MSG   = "Provider authentication failed. Please check the API key."
REJECT_MSG = "Provider rejected this link or torrent. Please check that it is valid and supported."
TEMP_MSG   = "Provider temporarily unavailable. Please retry later."
GENERIC    = "Provider error. Please retry or check the provider configuration."


class TestSafeProviderErrorMessage(unittest.TestCase):

    # ── AllDebrid auth ────────────────────────────────────────────────────────

    def test_alldebrid_auth_bad_apikey(self):
        exc = AllDebridAuthError(
            "AllDebrid API error: code=AUTH_BAD_APIKEY message=The auth apikey is invalid"
        )
        self.assertEqual(safe_provider_error_message(exc), AUTH_MSG)

    def test_alldebrid_auth_missing_apikey(self):
        exc = AllDebridAuthError("AllDebrid API error: code=AUTH_MISSING_APIKEY")
        self.assertEqual(safe_provider_error_message(exc), AUTH_MSG)

    def test_alldebrid_auth_blocked(self):
        exc = AllDebridAuthError("AllDebrid API error: code=AUTH_BLOCKED")
        self.assertEqual(safe_provider_error_message(exc), AUTH_MSG)

    def test_alldebrid_must_be_premium(self):
        exc = AllDebridAuthError("AllDebrid API error: code=MUST_BE_PREMIUM")
        self.assertEqual(safe_provider_error_message(exc), AUTH_MSG)

    # ── AllDebrid rejection ───────────────────────────────────────────────────

    def test_alldebrid_invalid_torrent_file(self):
        exc = AllDebridApiError(
            "AllDebrid API error: code=MAGNET_INVALID_FILE message=Torrent file is invalid"
        )
        self.assertEqual(safe_provider_error_message(exc), REJECT_MSG)

    def test_alldebrid_invalid_magnet(self):
        exc = AllDebridApiError("AllDebrid API error: code=MAGNET_INVALID_URI message=Magnet is invalid")
        self.assertEqual(safe_provider_error_message(exc), REJECT_MSG)

    def test_alldebrid_bad_link(self):
        exc = AllDebridApiError("AllDebrid API error: code=BAD_LINK message=Link is invalid")
        self.assertEqual(safe_provider_error_message(exc), REJECT_MSG)

    def test_alldebrid_link_not_supported(self):
        exc = AllDebridApiError("AllDebrid API error: code=LINK_HOST_NOT_SUPPORTED")
        self.assertEqual(safe_provider_error_message(exc), REJECT_MSG)

    def test_alldebrid_infringing_file(self):
        exc = AllDebridApiError("AllDebrid API error: code=INFRINGING_FILE")
        self.assertEqual(safe_provider_error_message(exc), REJECT_MSG)

    def test_alldebrid_torrent_too_large(self):
        exc = AllDebridApiError("AllDebrid API error: code=MAGNET_TOO_LARGE")
        self.assertEqual(safe_provider_error_message(exc), REJECT_MSG)

    # ── AllDebrid temporary ───────────────────────────────────────────────────

    def test_alldebrid_maintenance(self):
        exc = AllDebridApiError("AllDebrid API error: code=MAINTENANCE")
        self.assertEqual(safe_provider_error_message(exc), TEMP_MSG)

    def test_alldebrid_timeout(self):
        exc = AllDebridClientError("AllDebrid timeout: Request timed out")
        self.assertEqual(safe_provider_error_message(exc), TEMP_MSG)

    def test_alldebrid_too_many_active(self):
        exc = AllDebridApiError("AllDebrid API error: code=MAGNET_TOO_MANY_ACTIVE")
        self.assertEqual(safe_provider_error_message(exc), TEMP_MSG)

    def test_alldebrid_host_unavailable(self):
        exc = AllDebridApiError("AllDebrid API error: code=LINK_HOST_UNAVAILABLE")
        self.assertEqual(safe_provider_error_message(exc), TEMP_MSG)

    # ── AllDebrid generic ─────────────────────────────────────────────────────

    def test_alldebrid_generic_api_error(self):
        exc = AllDebridApiError("AllDebrid API error: code=MAGNET_INTERNAL_ERROR")
        self.assertEqual(safe_provider_error_message(exc), GENERIC)

    def test_alldebrid_invalid_json_response(self):
        exc = AllDebridApiError("Invalid JSON response from AllDebrid: HTTP 500, body=<empty>")
        self.assertEqual(safe_provider_error_message(exc), GENERIC)

    # ── RealDebrid auth ───────────────────────────────────────────────────────

    def test_realdebrid_auth_error_subclass(self):
        exc = RealDebridAuthError("REALDEBRID_TOKEN is empty")
        self.assertEqual(safe_provider_error_message(exc), AUTH_MSG)

    def test_realdebrid_auth_401(self):
        exc = RealDebridApiError("Real-Debrid API error: HTTP 401 - bad_token")
        self.assertEqual(safe_provider_error_message(exc), AUTH_MSG)

    # ── RealDebrid rejection ──────────────────────────────────────────────────

    def test_realdebrid_infringing(self):
        exc = RealDebridApiError("Torrent rejected by RealDebrid: infringing file")
        self.assertEqual(safe_provider_error_message(exc), REJECT_MSG)

    # ── Generic fallback ──────────────────────────────────────────────────────

    def test_non_provider_exception(self):
        self.assertEqual(safe_provider_error_message(RuntimeError("something broke")), GENERIC)

    def test_plain_exception(self):
        self.assertEqual(safe_provider_error_message(Exception("oops")), GENERIC)

    # ── No raw provider string should leak through ────────────────────────────

    def test_no_raw_alldebrid_string_in_output(self):
        """safe_provider_error_message must never return the raw AllDebrid API string."""
        exc = AllDebridAuthError(
            "AllDebrid API error: code=AUTH_BAD_APIKEY message=The auth apikey is invalid"
        )
        result = safe_provider_error_message(exc)
        self.assertNotIn("AUTH_BAD_APIKEY", result)
        self.assertNotIn("AllDebrid API error", result)

    def test_no_raw_code_in_rejection_output(self):
        exc = AllDebridApiError(
            "AllDebrid API error: code=MAGNET_INVALID_FILE message=Torrent file is invalid"
        )
        result = safe_provider_error_message(exc)
        self.assertNotIn("MAGNET_INVALID_FILE", result)
        self.assertNotIn("AllDebrid API error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
