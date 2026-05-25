import json
import sqlite3

ALLOWED_DESTINATION_TYPES = {"synology", "nas", "local"}


def _is_unique_constraint_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        isinstance(exc, sqlite3.IntegrityError)
        or "unique constraint" in message
        or "duplicate key" in message
        or "unique violation" in message
    )


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
