import logging
import hashlib
import re

from backend.services_v2.providers.realdebrid_client import (
    RealDebridApiError,
    RealDebridAuthError,
    RealDebridClientError,
)

from backend.services_v2.providers.alldebrid_client import (
    AllDebridApiError,
    AllDebridAuthError,
    AllDebridClientError,
)

logger = logging.getLogger(__name__)

_ERROR_CODE_RE = re.compile(r"\bcode=([A-Z0-9_]+)\b", re.IGNORECASE)

_REJECTION_SIGNALS = frozenset({
    "invalid_id", "invalid_uri", "invalid_file", "file_upload_failed", "upload_failed",
    "bad_link", "not_supported", "infringing", "too_large", "too_big",
    "invalid uri", "invalid file", "file is invalid", "rejected",
})

_TEMPORARY_SIGNALS = frozenset({
    "timeout", "timed out", "temporarily", "maintenance",
    "too many", "too_many", "too_many_active", "limit_reached",
    "no_server", "server_full", "host_full", "host_unavailable",
})


def classify_provider_error_message(exc: Exception) -> str:
    """Compute a safe user-facing provider error message without logging."""
    if isinstance(exc, (AllDebridAuthError, RealDebridAuthError)):
        return "Provider authentication failed. Please check the API key."

    msg = str(exc).lower()

    if isinstance(exc, (RealDebridApiError, RealDebridClientError)):
        if any(s in msg for s in ("401", "403", "bad_token", "token expired", "bad credentials")):
            return "Provider authentication failed. Please check the API key."

    if isinstance(exc, (
        AllDebridApiError, AllDebridClientError,
        RealDebridApiError, RealDebridClientError,
    )):
        if any(s in msg for s in _REJECTION_SIGNALS):
            return "Provider rejected this link or torrent. Please check that it is valid and supported."
        if any(s in msg for s in _TEMPORARY_SIGNALS):
            return "Provider temporarily unavailable. Please retry later."
        return "Provider error. Please retry or check the provider configuration."

    return "Provider error. Please retry or check the provider configuration."


def safe_provider_error_message(exc: Exception) -> str:
    """Map a raw provider exception to a safe user-facing message. Logs at WARNING.

    Logs the original error so technical details remain in backend logs without
    being exposed to the UI.
    """
    logger.warning("Provider error: %s", exc)
    return classify_provider_error_message(exc)


def is_persistable_provider_error(exc: Exception) -> bool:
    """Return True for provider content/API errors that should persist job as failed.

    Auth errors are excluded: a bad API key does not indicate the job content is
    invalid — fixing the key should allow the same job to be retried unchanged.
    """
    if isinstance(exc, (AllDebridAuthError, RealDebridAuthError)):
        return False
    if not isinstance(exc, (AllDebridApiError, RealDebridApiError)):
        return False
    message = str(exc).lower()
    return any(signal in message for signal in _REJECTION_SIGNALS)


def is_provider_client_error(exc: Exception) -> bool:
    """Return True for any AllDebrid or RealDebrid client exception (including auth)."""
    return isinstance(exc, (AllDebridClientError, RealDebridClientError))


def is_terminal_provider_error(exc: Exception) -> bool:
    """Only errors known to make further polling useless belong here."""
    return isinstance(exc, AllDebridApiError) and "MAGNET_INVALID_ID" in str(exc).upper()


def provider_error_fingerprint(job, exc: Exception) -> str:
    message = " ".join(str(exc).strip().lower().split())
    match = _ERROR_CODE_RE.search(str(exc))
    normalized = match.group(1).upper() if match else message
    logical_key = "|".join((job.id, "provider.failed", job.provider_config_id or job.provider_name or "", normalized))
    return hashlib.sha256(logical_key.encode("utf-8")).hexdigest()
