import logging

import requests.exceptions

from backend.services_v2.destinations.synology_destination import SynologyDestinationError

logger = logging.getLogger(__name__)

# Same rationale as PROVIDER_ERROR_STATUS: keep 422 so reverse proxies pass the
# JSON body through rather than substituting their own error page.
DESTINATION_ERROR_STATUS = 422

_AUTH_SIGNALS    = frozenset({"login failed"})
_FOLDER_SIGNALS  = frozenset({"folder creation"})
_NETWORK_SIGNALS = frozenset({"http error", "timeout", "timed out", "connection"})


def classify_destination_error_message(exc: Exception) -> str:
    """Pure — no logging."""
    if isinstance(exc, requests.exceptions.SSLError):
        return "Destination SSL certificate error. Please check the SSL configuration."

    if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return "Destination temporarily unavailable. Please retry later."

    if isinstance(exc, requests.exceptions.RequestException):
        return "Destination connection error. Please check the URL and network access."

    if isinstance(exc, PermissionError):
        return "Destination write access failed. Please check folder permissions and destination path."

    if isinstance(exc, SynologyDestinationError):
        msg = str(exc).lower()
        if any(s in msg for s in _AUTH_SIGNALS):
            return "Destination authentication failed. Please check the destination credentials."
        if any(s in msg for s in _FOLDER_SIGNALS):
            return "Destination write access failed. Please check folder permissions and destination path."
        if any(s in msg for s in _NETWORK_SIGNALS):
            return "Destination temporarily unavailable. Please retry later."
        return "Destination error. Please check the destination configuration."

    return "Destination error. Please check the destination configuration."


def safe_destination_error_message(exc: Exception) -> str:
    """Log at WARNING and return a safe user-facing message."""
    logger.warning("Destination error: %s", exc)
    return classify_destination_error_message(exc)


def is_destination_client_error(exc: Exception) -> bool:
    """True for expected destination errors — should not produce a 502."""
    return isinstance(exc, (
        SynologyDestinationError,
        requests.exceptions.RequestException,
        PermissionError,
    ))


def is_persistable_destination_error(exc: Exception) -> bool:
    """True for destination errors that should persist job as failed."""
    return is_destination_client_error(exc)
