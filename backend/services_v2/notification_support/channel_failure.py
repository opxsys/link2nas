import logging

import requests.exceptions

logger = logging.getLogger(__name__)

NOTIFICATION_CHANNEL_ERROR_STATUS = 422


def classify_notification_channel_error(exc: Exception) -> str:
    """Pure — no logging. Maps network/HTTP exceptions to safe user-facing messages."""
    if isinstance(exc, requests.exceptions.SSLError):
        return "Notification endpoint SSL certificate error. Please check the channel URL."

    if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return "Notification endpoint is not reachable. Please check the channel URL."

    if isinstance(exc, requests.exceptions.RequestException):
        return "Notification endpoint is not reachable. Please check the channel URL."

    return "Notification channel error. Please check the channel configuration."


def safe_notification_channel_error(exc: Exception) -> str:
    """Log at WARNING and return a safe user-facing message."""
    logger.warning("Notification channel error: %s", exc)
    return classify_notification_channel_error(exc)


def is_notification_channel_error(exc: Exception) -> bool:
    """True for expected network/connection errors during channel tests."""
    return isinstance(exc, requests.exceptions.RequestException)
