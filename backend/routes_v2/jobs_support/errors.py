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
    RealDebridClientError,
)

from backend.services_v2.providers.alldebrid_client import (
    AllDebridApiError,
    AllDebridClientError,
)

from backend.services_v2.destinations.synology_destination import SynologyDestinationError


def _error(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code


def _handle_provider_exception(exc):
    if isinstance(exc, ValueError):
        return _error(str(exc), 400)

    if isinstance(exc, RuntimeError):
        return _error(str(exc), 500)

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
        return _error(str(exc), 502)

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
