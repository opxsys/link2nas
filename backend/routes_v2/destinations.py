import json

import sqlite3

from flask import Blueprint, jsonify, request, current_app

from backend.routes_v2._context import get_user_context
from backend.services_v2.destination_config_service import DestinationConfigService

from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)
from backend.services_v2.destinations.synology_destination import SynologyDestinationError


destinations_v2_bp = Blueprint("destinations_v2", __name__, url_prefix="/api/v2/destinations")

ALLOWED_DESTINATION_TYPES = {"synology", "nas", "local"}


def _is_unique_constraint_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        isinstance(exc, sqlite3.IntegrityError)
        or "unique constraint" in message
        or "duplicate key" in message
        or "unique violation" in message
    )


def _error(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code


def _normalize_destination_type(value: str | None) -> str:
    destination_type = str(value or "").strip().lower()

    if destination_type == "nas":
        destination_type = "synology"

    return destination_type


def _parse_config_json(raw: str | None) -> dict:
    if not raw:
        return {}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("config_json must be valid JSON")

    if not isinstance(parsed, dict):
        raise ValueError("config_json must be a JSON object")

    return parsed


def _validate_destination_config(destination_type: str, config: dict) -> None:
    destination_type = _normalize_destination_type(destination_type)

    if destination_type == "local":
        base_path = str(config.get("base_path") or "downloads").strip()

        if base_path.startswith("/") or "\\" in base_path:
            raise ValueError("local destination path must be relative")

        parts = [part for part in base_path.replace("\\", "/").split("/") if part]

        if any(part in {".", ".."} for part in parts):
            raise ValueError("invalid local destination path")

        config["base_path"] = base_path or "downloads"
        return

    if destination_type == "synology":
        required = ["synology_url", "username"]

        for field in required:
            if not config.get(field):
                raise ValueError(f"nas destination requires {field}")

        if "verify_ssl" in config and not isinstance(config["verify_ssl"], bool):
            raise ValueError("nas verify_ssl must be boolean")

        return

    raise ValueError("invalid destination_type")


def _safe_config(destination_type: str, raw_config_json: str | None) -> dict:
    destination_type = _normalize_destination_type(destination_type)

    try:
        config = _parse_config_json(raw_config_json)
    except ValueError:
        return {}

    if destination_type == "synology":
        return {
            "synology_url": config.get("synology_url"),
            "username": config.get("username"),
            "has_password": bool(config.get("password")),
            "verify_ssl": config.get("verify_ssl", True),
            "destination_base": config.get("destination_base"),
        }

    if destination_type == "local":
        return {
            "base_path": config.get("base_path"),
        }

    return {}


def _serialize(config):
    return {
        "id": config.id,
        "user_id": config.user_id,

        # V3 fields
        "name": config.name,
        "destination_type": config.destination_type,

        # Temporary V2 compatibility field
        "destination_name": config.destination_type,

        "is_enabled": config.is_enabled,
        "is_default": config.is_default,
        "config": _safe_config(config.destination_type, config.config_json),
        "created_at": config.created_at,
        "updated_at": config.updated_at,
    }


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

    if destination_type not in {"synology", "local"}:
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
    if not config and _normalize_destination_type(config_ref) in {"synology", "local"}:
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
        except SynologyDestinationError as exc:
            return _error(str(exc), 502)
        except Exception:
            return _error("Destination test failed", 502)

    except DestinationConfigDisabledError as exc:
        return _error(str(exc), 400)
    except UnknownDestinationError as exc:
        return _error(str(exc), 400)
    except SynologyDestinationError as exc:
        return _error(str(exc), 502)
    except Exception:
        return _error("Destination test failed", 502)

    destination = resolved.destination

    if not hasattr(destination, "test_connection"):
        return jsonify({
            "ok": True,
            "destination_name": resolved.name,
            "destination_type": resolved.destination_type,
            "destination_profile_name": resolved.destination_profile_name,
            "message": "Destination has no test but is configured",
        })

    result = destination.test_connection()
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
    if not config and _normalize_destination_type(config_ref) in {"synology", "local"}:
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
