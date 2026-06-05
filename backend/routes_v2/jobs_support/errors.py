import logging

from flask import jsonify

from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)

from backend.services_v2.provider_factory import (
    ProviderConfigDisabledError,
    ProviderConfigNotFoundError,
    UnknownProviderError,
)

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

from backend.services_v2.destinations.synology_destination import SynologyDestinationError


logger = logging.getLogger(__name__)

# Provider/API errors that are expected application-level failures must not use
# 5xx so that reverse proxies (Cloudflare, nginx) pass the JSON body through
# instead of substituting their own error page.
PROVIDER_ERROR_STATUS = 422

# ── Rejection signals: invalid or unsupported content submitted to the provider ──
_REJECTION_SIGNALS = frozenset({
    "invalid_uri", "invalid_file", "file_upload_failed", "upload_failed",
    "bad_link", "not_supported", "infringing", "too_large", "too_big",
    "invalid uri", "invalid file", "file is invalid", "rejected",
})

# ── Temporary-availability signals ──
_TEMPORARY_SIGNALS = frozenset({
    "timeout", "timed out", "temporarily", "maintenance",
    "too many", "too_many", "too_many_active", "limit_reached",
    "no_server", "server_full", "host_full", "host_unavailable",
})


def safe_provider_error_message(exc: Exception) -> str:
    """
    Map a raw provider exception to a safe, user-facing message.

    Logs the original error at WARNING level so technical details remain
    available in backend logs without being exposed to the UI.
    """
    logger.warning("Provider error: %s", exc)

    # Auth errors — AllDebrid has a dedicated subclass; RealDebrid uses the base
    # client error or raises with a token-empty message.
    if isinstance(exc, (AllDebridAuthError, RealDebridAuthError)):
        return "Provider authentication failed. Please check the API key."

    msg = str(exc).lower()

    # RealDebrid raises RealDebridApiError for HTTP 401/403 (not a subclass of AuthError)
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


def _error(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code


def _handle_provider_exception(exc):
    if isinstance(exc, ValueError):
        return _error(str(exc), 400)

    if isinstance(exc, (
        ProviderConfigNotFoundError,
        ProviderConfigDisabledError,
        UnknownProviderError,
    )):
        return _error(str(exc), 400)

    if isinstance(exc, (
        RealDebridApiError,
        RealDebridClientError,
        AllDebridApiError,
        AllDebridClientError,
    )):
        return _error(safe_provider_error_message(exc), PROVIDER_ERROR_STATUS)

    if isinstance(exc, RuntimeError):
        return _error(str(exc), 500)

    raise exc


def is_persistable_provider_error(exc: Exception) -> bool:
    """Return True for provider content/API errors that should persist job as failed.

    Auth errors are excluded: a bad API key does not indicate the job content is
    invalid — fixing the key should allow the same job to be retried unchanged.
    """
    if isinstance(exc, (AllDebridAuthError, RealDebridAuthError)):
        return False
    return isinstance(exc, (
        AllDebridApiError, AllDebridClientError,
        RealDebridApiError, RealDebridClientError,
    ))


def _handle_destination_exception(exc):
    if isinstance(exc, ValueError):
        return _error(str(exc), 400)

    if isinstance(exc, RuntimeError):
        return _error(str(exc), 500)

    if isinstance(exc, (
        DestinationConfigNotFoundError,
        DestinationConfigDisabledError,
        UnknownDestinationError,
    )):
        return _error(str(exc), 400)

    if isinstance(exc, SynologyDestinationError):
        return _error(str(exc), 502)

    raise exc
