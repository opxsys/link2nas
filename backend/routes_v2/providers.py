import sqlite3

from flask import Blueprint, jsonify, request, current_app

from backend.routes_v2._context import get_user_context
from backend.services_v2.provider_config_service import ProviderConfigService


providers_v2_bp = Blueprint("providers_v2", __name__, url_prefix="/api/v2/providers")

ALLOWED_PROVIDERS = {"realdebrid", "alldebrid"}


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


def _serialize(config):
    return {
        "id": config.id,
        "user_id": config.user_id,

        # V3 fields
        "name": config.name,
        "provider_type": config.provider_type,

        # Temporary V2 compatibility field
        "provider_name": config.provider_type,

        "is_enabled": config.is_enabled,
        "is_default": config.is_default,
        "has_api_key": bool(config.encrypted_api_key),
        "account_expires_at": config.account_expires_at,
        "created_at": config.created_at,
        "updated_at": config.updated_at,
    }


@providers_v2_bp.post("")
def save_provider_config_v2():
    ctx = get_user_context()
    service: ProviderConfigService = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]

    data = request.get_json(silent=True) or {}

    provider_config_id = data.get("provider_config_id") or data.get("id")
    provider_type = data.get("provider_type") or data.get("provider_name")
    name = data.get("name")
    api_key = data.get("api_key")

    if not provider_type:
        return _error("provider_type is required")

    provider_type = str(provider_type).strip().lower()

    if provider_type not in ALLOWED_PROVIDERS:
        return _error("invalid provider_type")

    if api_key is not None and not str(api_key).strip():
        return _error("api_key cannot be empty")

    try:
        config = service.save_provider_config(
            context=ctx,
            provider_type=provider_type,
            name=name,
            provider_config_id=provider_config_id,
            encrypted_api_key=api_key,
            is_enabled=data.get("is_enabled", True),
            is_default=data.get("is_default", False),
            account_expires_at=data.get("account_expires_at"),
        )
    except ValueError as exc:
        return _error(str(exc), 400)
    except Exception as exc:
        if _is_unique_constraint_error(exc):
            return _error("A provider profile with this name already exists.", 400)
        return _error("Provider profile save failed.", 500)

    return jsonify(_serialize(config)), 201


@providers_v2_bp.get("")
def list_provider_configs_v2():
    ctx = get_user_context()
    service: ProviderConfigService = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]

    configs = service.list_provider_configs(ctx)
    return jsonify([_serialize(c) for c in configs])


@providers_v2_bp.get("/<config_ref>")
def get_provider_config_v2(config_ref):
    ctx = get_user_context()
    service: ProviderConfigService = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]

    config = service.get_provider_config(
        ctx,
        provider_config_id=config_ref,
    )

    # Temporary V2 compatibility: allow /realdebrid or /alldebrid.
    if not config and config_ref in ALLOWED_PROVIDERS:
        config = service.get_provider_config(
            ctx,
            provider_name=config_ref,
        )

    if not config:
        return _error("Not found", 404)

    return jsonify(_serialize(config))


@providers_v2_bp.delete("/<config_ref>")
def delete_provider_config_v2(config_ref):
    ctx = get_user_context()
    service: ProviderConfigService = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]

    config = service.get_provider_config(
        ctx,
        provider_config_id=config_ref,
    )

    # Temporary V2 compatibility: allow DELETE /realdebrid or /alldebrid.
    if not config and config_ref in ALLOWED_PROVIDERS:
        config = service.get_provider_config(
            ctx,
            provider_name=config_ref,
        )

    if not config:
        return _error("Not found", 404)

    try:
        service.delete_provider_config(ctx, config.id)
    except ValueError as exc:
        return _error(str(exc), 400)

    return "", 204
