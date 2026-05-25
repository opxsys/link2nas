from flask import current_app, jsonify

from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)
from backend.services_v2.destinations.synology_destination import SynologyDestinationError

from backend.routes_v2.settings_support.responses import _error


def test_destination(ctx, data):
    destination_config_id = data.get("destination_config_id") or data.get("id") or None
    destination_name = data.get("destination_name") or None

    factory = current_app.config["USER_DESTINATION_FACTORY_V2"]

    try:
        resolved = factory.resolve_destination_for_user(
            user_id=ctx.user_id,
            destination_config_id=destination_config_id,
            destination_name=destination_name,
            allow_links_only=False,
        )
    except DestinationConfigNotFoundError as exc:
        return _error(str(exc), 404)
    except DestinationConfigDisabledError as exc:
        return _error(str(exc), 400)
    except UnknownDestinationError as exc:
        return _error(str(exc), 400)

    if resolved.config is None:
        return jsonify({
            "ok": True,
            "destination_name": "links_only",
            "destination_type": None,
            "destination_profile_name": None,
            "message": "links-only mode does not require connectivity test",
        })

    if resolved.name == "local":
        result = resolved.destination.test_connection()
        status_code = 200 if result.get("ok") else 502

        result.setdefault("destination_config_id", resolved.destination_config_id)
        result.setdefault("destination_name", resolved.destination_type)
        result.setdefault("destination_type", resolved.destination_type)
        result.setdefault("destination_profile_name", resolved.destination_profile_name)

        return jsonify(result), status_code

    if resolved.name == "synology":
        try:
            result = resolved.destination.test_connection()
        except SynologyDestinationError as exc:
            return _error(str(exc), 502)
        except Exception as exc:
            return _error(f"NAS test failed: {exc}", 502)

        result.setdefault("destination_config_id", resolved.destination_config_id)
        result.setdefault("destination_name", resolved.destination_type)
        result.setdefault("destination_type", resolved.destination_type)
        result.setdefault("destination_profile_name", resolved.destination_profile_name)

        return jsonify(result)

    return _error(f"Unsupported destination test: {resolved.name}", 400)
