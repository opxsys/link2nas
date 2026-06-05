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

from backend.services_v2.destinations.synology_destination import SynologyDestinationError

# Re-exported so existing callers (create_routes, lifecycle_routes, tests) keep working.
from backend.services_v2.job_support.provider_failure import (  # noqa: F401
    safe_provider_error_message,
    is_persistable_provider_error,
    is_provider_client_error,
)

logger = logging.getLogger(__name__)

# Provider/API errors that are expected application-level failures must not use
# 5xx so that reverse proxies (Cloudflare, nginx) pass the JSON body through
# instead of substituting their own error page.
PROVIDER_ERROR_STATUS = 422


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

    if is_provider_client_error(exc):
        return _error(safe_provider_error_message(exc), PROVIDER_ERROR_STATUS)

    if isinstance(exc, RuntimeError):
        return _error(str(exc), 500)

    raise exc


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
