#!/usr/bin/env python3
"""
Unit tests for classify_email_error / safe_email_error_message / is_email_client_error.

Run from project root:
    source .venv/bin/activate
    python scripts/tests/unit/test_safe_email_error_message.py
"""

import os
import sys
import smtplib
import socket
import ssl
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services_v2.smtp_service import SmtpServiceError
from backend.services_v2.email_support.email_failure import (
    classify_email_error,
    safe_email_error_message,
    is_email_client_error,
    EMAIL_ERROR_STATUS,
)

_AUTH_MSG = "Email authentication failed. Please check the SMTP username and password."
_UNREACHABLE_MSG = "Email server is not reachable. Please check the SMTP host and port."
_TLS_MSG = "Email TLS/SSL error. Please check the SMTP security settings."
_ADDRESS_MSG = "Email address was rejected. Please check the sender and recipient addresses."
_SMTP_MSG = "Email sending failed. Please check the SMTP configuration."


def _wrap(cause: Exception) -> SmtpServiceError:
    """Simulate SmtpService.send_email() exception chaining."""
    exc = SmtpServiceError(f"SMTP send failed: {cause}")
    exc.__cause__ = cause
    return exc


class TestClassifyEmailError(unittest.TestCase):

    def test_auth_error(self):
        cause = smtplib.SMTPAuthenticationError(535, b"Bad credentials")
        self.assertEqual(classify_email_error(_wrap(cause)), _AUTH_MSG)

    def test_connect_error(self):
        cause = smtplib.SMTPConnectError(-1, b"Connection refused")
        self.assertEqual(classify_email_error(_wrap(cause)), _UNREACHABLE_MSG)

    def test_server_disconnected(self):
        cause = smtplib.SMTPServerDisconnected("Connection closed unexpectedly")
        self.assertEqual(classify_email_error(_wrap(cause)), _UNREACHABLE_MSG)

    def test_connection_refused(self):
        cause = ConnectionRefusedError("Connection refused")
        self.assertEqual(classify_email_error(_wrap(cause)), _UNREACHABLE_MSG)

    def test_timeout_error(self):
        cause = TimeoutError("Timed out")
        self.assertEqual(classify_email_error(_wrap(cause)), _UNREACHABLE_MSG)

    def test_socket_timeout(self):
        cause = socket.timeout("timed out")
        self.assertEqual(classify_email_error(_wrap(cause)), _UNREACHABLE_MSG)

    def test_ssl_error(self):
        cause = ssl.SSLError("certificate verify failed")
        self.assertEqual(classify_email_error(_wrap(cause)), _TLS_MSG)

    def test_recipients_refused(self):
        cause = smtplib.SMTPRecipientsRefused({"user@example.com": (550, b"User unknown")})
        self.assertEqual(classify_email_error(_wrap(cause)), _ADDRESS_MSG)

    def test_sender_refused(self):
        cause = smtplib.SMTPSenderRefused(550, b"Rejected", "sender@example.com")
        self.assertEqual(classify_email_error(_wrap(cause)), _ADDRESS_MSG)

    def test_generic_smtp_exception(self):
        cause = smtplib.SMTPException("Some SMTP error")
        self.assertEqual(classify_email_error(_wrap(cause)), _SMTP_MSG)

    def test_smtp_service_error_no_cause(self):
        exc = SmtpServiceError("SMTP is not enabled")
        self.assertEqual(classify_email_error(exc), _SMTP_MSG)

    def test_unwrapped_auth_error(self):
        # Direct SMTP exception (not wrapped in SmtpServiceError) also classified correctly.
        cause = smtplib.SMTPAuthenticationError(535, b"Bad credentials")
        self.assertEqual(classify_email_error(cause), _AUTH_MSG)

    def test_unwrapped_ssl_error(self):
        cause = ssl.SSLError("certificate verify failed")
        self.assertEqual(classify_email_error(cause), _TLS_MSG)


class TestIsEmailClientError(unittest.TestCase):

    def test_smtp_service_error_is_client_error(self):
        self.assertTrue(is_email_client_error(SmtpServiceError("SMTP is not enabled")))

    def test_wrapped_auth_error_is_client_error(self):
        cause = smtplib.SMTPAuthenticationError(535, b"Bad credentials")
        self.assertTrue(is_email_client_error(_wrap(cause)))

    def test_runtime_error_not_client_error(self):
        self.assertFalse(is_email_client_error(RuntimeError("boom")))

    def test_smtp_exception_not_client_error(self):
        self.assertFalse(is_email_client_error(smtplib.SMTPException("raw smtp")))

    def test_exception_not_client_error(self):
        self.assertFalse(is_email_client_error(Exception("generic")))

    def test_value_error_not_client_error(self):
        self.assertFalse(is_email_client_error(ValueError("bad")))


class TestSafeEmailErrorMessage(unittest.TestCase):

    def test_no_host_in_output(self):
        cause = smtplib.SMTPConnectError(-1, b"Connection refused")
        exc = SmtpServiceError(f"SMTP send failed connecting to smtp.secret.internal:587: {cause}")
        exc.__cause__ = cause
        result = safe_email_error_message(exc)
        self.assertNotIn("smtp.secret.internal", result)
        self.assertNotIn("587", result)

    def test_no_username_in_output(self):
        cause = smtplib.SMTPAuthenticationError(535, b"Bad credentials for user@secret.internal")
        exc = SmtpServiceError(f"SMTP send failed: {cause}")
        exc.__cause__ = cause
        result = safe_email_error_message(exc)
        self.assertNotIn("user@secret.internal", result)

    def test_no_password_in_output(self):
        cause = smtplib.SMTPAuthenticationError(535, b"password=hunter2 rejected")
        exc = SmtpServiceError(f"SMTP send failed: {cause}")
        exc.__cause__ = cause
        result = safe_email_error_message(exc)
        self.assertNotIn("hunter2", result)

    def test_no_stacktrace_in_output(self):
        cause = smtplib.SMTPConnectError(-1, b"Traceback (most recent call last): ...")
        exc = SmtpServiceError(f"SMTP send failed: {cause}")
        exc.__cause__ = cause
        result = safe_email_error_message(exc)
        self.assertNotIn("Traceback", result)

    def test_returns_safe_string(self):
        cause = smtplib.SMTPAuthenticationError(535, b"Bad credentials")
        result = safe_email_error_message(_wrap(cause))
        self.assertEqual(result, _AUTH_MSG)

    def test_returns_string_type(self):
        exc = SmtpServiceError("SMTP is not enabled")
        result = safe_email_error_message(exc)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)


class TestEmailErrorStatus(unittest.TestCase):

    def test_error_status_is_422(self):
        self.assertEqual(EMAIL_ERROR_STATUS, 422)


if __name__ == "__main__":
    unittest.main(verbosity=2)
