#!/usr/bin/env python3
"""
Unit tests for classify_notification_channel_error / safe_notification_channel_error.

Run from project root:
    source .venv/bin/activate
    python scripts/tests/unit/test_safe_notification_channel_error.py
"""

import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services_v2.notification_support.channel_failure import (
    classify_notification_channel_error,
    safe_notification_channel_error,
    is_notification_channel_error,
    NOTIFICATION_CHANNEL_ERROR_STATUS,
)

import requests.exceptions

UNREACHABLE_MSG = "Notification endpoint is not reachable. Please check the channel URL."
SSL_MSG = "Notification endpoint SSL certificate error. Please check the channel URL."
GENERIC_MSG = "Notification channel error. Please check the channel configuration."


class TestClassifyNotificationChannelError(unittest.TestCase):

    def test_connection_error(self):
        exc = requests.exceptions.ConnectionError("Connection refused")
        self.assertEqual(classify_notification_channel_error(exc), UNREACHABLE_MSG)

    def test_timeout(self):
        exc = requests.exceptions.Timeout("Read timed out")
        self.assertEqual(classify_notification_channel_error(exc), UNREACHABLE_MSG)

    def test_ssl_error(self):
        exc = requests.exceptions.SSLError("SSL certificate verify failed")
        self.assertEqual(classify_notification_channel_error(exc), SSL_MSG)

    def test_generic_request_exception(self):
        exc = requests.exceptions.RequestException("Some network error")
        self.assertEqual(classify_notification_channel_error(exc), UNREACHABLE_MSG)

    def test_non_requests_exception(self):
        exc = RuntimeError("Unexpected internal error")
        self.assertEqual(classify_notification_channel_error(exc), GENERIC_MSG)

    def test_value_error(self):
        exc = ValueError("bad value")
        self.assertEqual(classify_notification_channel_error(exc), GENERIC_MSG)


class TestIsNotificationChannelError(unittest.TestCase):

    def test_connection_error_is_channel_error(self):
        self.assertTrue(is_notification_channel_error(requests.exceptions.ConnectionError()))

    def test_timeout_is_channel_error(self):
        self.assertTrue(is_notification_channel_error(requests.exceptions.Timeout()))

    def test_ssl_error_is_channel_error(self):
        self.assertTrue(is_notification_channel_error(requests.exceptions.SSLError()))

    def test_request_exception_is_channel_error(self):
        self.assertTrue(is_notification_channel_error(requests.exceptions.RequestException()))

    def test_runtime_error_not_channel_error(self):
        self.assertFalse(is_notification_channel_error(RuntimeError("boom")))

    def test_value_error_not_channel_error(self):
        self.assertFalse(is_notification_channel_error(ValueError("bad")))

    def test_exception_not_channel_error(self):
        self.assertFalse(is_notification_channel_error(Exception("generic")))


class TestSafeNotificationChannelError(unittest.TestCase):

    def test_no_raw_url_in_output(self):
        exc = requests.exceptions.ConnectionError("Failed to connect to http://gotify.secret.internal:8080")
        result = safe_notification_channel_error(exc)
        self.assertNotIn("gotify.secret.internal", result)
        self.assertNotIn("8080", result)

    def test_no_token_in_output(self):
        exc = requests.exceptions.ConnectionError("token=abc123 connection refused")
        result = safe_notification_channel_error(exc)
        self.assertNotIn("abc123", result)

    def test_no_stacktrace_in_output(self):
        exc = requests.exceptions.ConnectionError("Traceback (most recent call last):\n  ...")
        result = safe_notification_channel_error(exc)
        self.assertNotIn("Traceback", result)

    def test_returns_safe_message_for_connection_error(self):
        exc = requests.exceptions.ConnectionError()
        self.assertEqual(safe_notification_channel_error(exc), UNREACHABLE_MSG)

    def test_returns_safe_message_for_timeout(self):
        exc = requests.exceptions.Timeout()
        self.assertEqual(safe_notification_channel_error(exc), UNREACHABLE_MSG)


class TestNotificationChannelErrorStatus(unittest.TestCase):

    def test_error_status_is_422(self):
        self.assertEqual(NOTIFICATION_CHANNEL_ERROR_STATUS, 422)


if __name__ == "__main__":
    unittest.main(verbosity=2)
