import json

from flask import Blueprint, jsonify, request, current_app

from backend.routes_v2._context import get_user_context
from backend.routes_v2.destinations_support.responses import _error
from backend.routes_v2.destinations_support.serialization import _serialize
from backend.routes_v2.destinations_support.validation import (
    _is_unique_constraint_error,
    _normalize_destination_type,
    _parse_config_json,
    _validate_destination_config,
)
from backend.services_v2.destination_config_service import DestinationConfigService
from backend.services_v2.destination_registry import DESTINATION_KEYS

from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)
from backend.services_v2.job_support.destination_failure import (
    safe_destination_error_message,
    is_destination_client_error,
    DESTINATION_ERROR_STATUS,
)


destinations_v2_bp = Blueprint("destinations_v2", __name__, url_prefix="/api/v2/destinations")


@destinations_v2_bp.post("")
def save_destination_config_v2():
    ctx = get_user_context()
    service: DestinationConfigService = current_app.config["DESTINATION_CONFIG_SERVICE_V2"]

    data = request.get_json(silent=True) or {}

    destination_config_id = data.get("destination_config_id") or data.get("id")
    destination_type = data.get("destination_type") or data.get("destination_name")
    name = data.get("name")

    if not destination_type:
        return _error("destination_type is required")

    destination_type = _normalize_destination_type(destination_type)

    if destination_type not in DESTINATION_KEYS:
        return _error("invalid destination_type")

    if destination_type == "local":
        user_repo = current_app.config["USER_REPO_V2"]
        user = user_repo.get_by_id(ctx.user_id)
        if not user or not user.can_use_local_space:
            return _error("Local space is not allowed for this account.", 403)

    raw_config_json = data.get("config_json", "{}")

    try:
        parsed_config = _parse_config_json(raw_config_json)
        _validate_destination_config(destination_type, parsed_config)
    except ValueError as exc:
        return _error(str(exc))

    try:
        config = service.save_destination_config(
            context=ctx,
            destination_type=destination_type,
            name=name,
            destination_config_id=destination_config_id,
            config_json=json.dumps(parsed_config),
            is_enabled=data.get("is_enabled", True),
            is_default=data.get("is_default", False),
        )
    except ValueError as exc:
        return _error(str(exc), 400)
    except Exception as exc:
        if _is_unique_constraint_error(exc):
            return _error("A destination profile with this name already exists.", 400)
        return _error("Destination profile save failed.", 500)

    return jsonify(_serialize(config)), 201


@destinations_v2_bp.get("")
def list_destination_configs_v2():
    ctx = get_user_context()
    service: DestinationConfigService = current_app.config["DESTINATION_CONFIG_SERVICE_V2"]

    configs = service.list_destination_configs(ctx)
    return jsonify([_serialize(c) for c in configs])


@destinations_v2_bp.get("/<config_ref>")
def get_destination_config_v2(config_ref):
    ctx = get_user_context()
    service: DestinationConfigService = current_app.config["DESTINATION_CONFIG_SERVICE_V2"]

    config = service.get_destination_config(
        ctx,
        destination_config_id=config_ref,
    )

    # Temporary V2 compatibility: allow /synology, /nas, /local.
    if not config and _normalize_destination_type(config_ref) in DESTINATION_KEYS:
        config = service.get_destination_config(
            ctx,
            destination_name=config_ref,
        )

    if not config:
        return _error("Not found", 404)

    return jsonify(_serialize(config))


@destinations_v2_bp.post("/<config_ref>/test")
def test_destination_config_v2(config_ref):
    ctx = get_user_context()
    factory = current_app.config["USER_DESTINATION_FACTORY_V2"]

    try:
        resolved = factory.resolve_destination_for_user(
            user_id=ctx.user_id,
            destination_config_id=config_ref,
        )
    except DestinationConfigNotFoundError:
        # Temporary V2 compatibility: allow /synology, /nas, /local.
        try:
            resolved = factory.resolve_destination_for_user(
                user_id=ctx.user_id,
                destination_name=config_ref,
            )
        except DestinationConfigNotFoundError as exc:
            return _error(str(exc), 404)
        except DestinationConfigDisabledError as exc:
            return _error(str(exc), 400)
        except UnknownDestinationError as exc:
            return _error(str(exc), 400)
    except DestinationConfigDisabledError as exc:
        return _error(str(exc), 400)
    except UnknownDestinationError as exc:
        return _error(str(exc), 400)

    destination = resolved.destination

    if not hasattr(destination, "test_connection"):
        return jsonify({
            "ok": True,
            "destination_name": resolved.name,
            "destination_type": resolved.destination_type,
            "destination_profile_name": resolved.destination_profile_name,
            "message": "Destination has no test but is configured",
        })

    try:
        result = destination.test_connection()
    except Exception as exc:
        if is_destination_client_error(exc):
            return _error(safe_destination_error_message(exc), DESTINATION_ERROR_STATUS)
        return _error("Destination test failed", 502)

    return jsonify(result), 200 if result.get("ok") else 400


@destinations_v2_bp.delete("/<config_ref>")
def delete_destination_config_v2(config_ref):
    ctx = get_user_context()
    service: DestinationConfigService = current_app.config["DESTINATION_CONFIG_SERVICE_V2"]

    config = service.get_destination_config(
        ctx,
        destination_config_id=config_ref,
    )

    # Temporary V2 compatibility: allow DELETE /synology, /nas, /local.
    if not config and _normalize_destination_type(config_ref) in DESTINATION_KEYS:
        config = service.get_destination_config(
            ctx,
            destination_name=config_ref,
        )

    if not config:
        return _error("Not found", 404)

    try:
        service.delete_destination_config(ctx, config.id)
    except ValueError as exc:
        return _error(str(exc), 400)

    return "", 204
