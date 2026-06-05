import logging
import smtplib
import socket
import ssl

from backend.services_v2.smtp_service import SmtpServiceError

logger = logging.getLogger(__name__)

EMAIL_ERROR_STATUS = 422

_AUTH_MSG = "Email authentication failed. Please check the SMTP username and password."
_UNREACHABLE_MSG = "Email server is not reachable. Please check the SMTP host and port."
_TLS_MSG = "Email TLS/SSL error. Please check the SMTP security settings."
_ADDRESS_MSG = "Email address was rejected. Please check the sender and recipient addresses."
_SMTP_MSG = "Email sending failed. Please check the SMTP configuration."


def classify_email_error(exc: Exception) -> str:
    """Pure — no logging. Maps SMTP exceptions to safe user-facing messages."""
    cause = exc.__cause__ if isinstance(exc, SmtpServiceError) else exc

    if isinstance(cause, smtplib.SMTPAuthenticationError):
        return _AUTH_MSG

    if isinstance(cause, (
        smtplib.SMTPConnectError,
        smtplib.SMTPServerDisconnected,
        ConnectionRefusedError,
        TimeoutError,
        socket.timeout,
    )):
        return _UNREACHABLE_MSG

    if isinstance(cause, ssl.SSLError):
        return _TLS_MSG

    if isinstance(cause, (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused)):
        return _ADDRESS_MSG

    if isinstance(cause, smtplib.SMTPException):
        return _SMTP_MSG

    return _SMTP_MSG


def safe_email_error_message(exc: Exception) -> str:
    """Log at WARNING and return a safe user-facing message."""
    logger.warning("Email send error: %s", exc)
    return classify_email_error(exc)


def is_email_client_error(exc: Exception) -> bool:
    """True for expected SMTP errors raised by SmtpService.send_email()."""
    return isinstance(exc, SmtpServiceError)
