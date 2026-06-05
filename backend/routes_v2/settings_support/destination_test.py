from flask import current_app, jsonify

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

    try:
        result = resolved.destination.test_connection()
    except Exception as exc:
        if is_destination_client_error(exc):
            return _error(safe_destination_error_message(exc), DESTINATION_ERROR_STATUS)
        return _error("Destination test failed", 502)

    result.setdefault("destination_config_id", resolved.destination_config_id)
    result.setdefault("destination_name", resolved.destination_type)
    result.setdefault("destination_type", resolved.destination_type)
    result.setdefault("destination_profile_name", resolved.destination_profile_name)

    status_code = 200 if result.get("ok") else 400
    return jsonify(result), status_code
