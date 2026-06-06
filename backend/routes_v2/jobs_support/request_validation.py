from flask import current_app

from backend.services_v2.destination_factory import DestinationConfigNotFoundError
from backend.services_v2.destination_registry import DESTINATION_ALL_KEYS
from backend.services_v2.provider_registry import PROVIDER_KEYS
from backend.routes_v2.jobs_support.errors import _error

ALLOWED_SOURCE_TYPES = {"magnet", "torrent_file", "direct_link"}
ALLOWED_PROVIDERS = PROVIDER_KEYS
ALLOWED_DESTINATIONS = DESTINATION_ALL_KEYS | {"links_only"}


def validate_provider_name(provider_name):
    if provider_name is not None and provider_name not in ALLOWED_PROVIDERS:
        return _error("invalid provider_name")
    return None


def validate_destination_name(destination_name):
    if destination_name is not None and destination_name not in ALLOWED_DESTINATIONS:
        return _error("invalid destination_name")
    return None


def _check_local_space_permission(ctx, destination_config_id=None, destination_name=None):
    """Return a 403 error response if destination is local and user lacks permission, else None."""
    is_local = destination_name == "local"
    if not is_local and destination_config_id:
        dest_service = current_app.config.get("DESTINATION_CONFIG_SERVICE_V2")
        if dest_service:
            config = dest_service.get_destination_config(ctx, destination_config_id=destination_config_id)
            if config and config.destination_type == "local":
                is_local = True
    if is_local:
        user_repo = current_app.config["USER_REPO_V2"]
        user = user_repo.get_by_id(ctx.user_id)
        if not user or not user.can_use_local_space:
            return _error("Local space is not allowed for this account.", 403)
    return None


def _resolve_destination_ref_for_request(
    ctx,
    destination_name,
    destination_config_id,
    send_to_destination: bool,
):
    if destination_name == "links_only":
        return None, None

    if destination_config_id:
        return None, destination_config_id

    if destination_name:
        return destination_name, None

    if not send_to_destination:
        return None, None

    destination_factory = current_app.config["USER_DESTINATION_FACTORY_V2"]
    resolved = destination_factory.resolve_destination_for_user(
        user_id=ctx.user_id,
        destination_name=None,
    )

    if resolved.config is None:
        raise DestinationConfigNotFoundError("No default destination config found")

    return None, resolved.destination_config_id
