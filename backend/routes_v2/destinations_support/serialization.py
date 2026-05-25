from backend.routes_v2.destinations_support.validation import _normalize_destination_type, _parse_config_json


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
