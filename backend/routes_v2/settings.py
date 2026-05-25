from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2._context import get_user_context
from backend.routes_v2.destinations import _serialize as serialize_destination
from backend.routes_v2.providers import _serialize as serialize_provider
from backend.routes_v2.settings_support.destination_test import test_destination
from backend.routes_v2.settings_support.notification_test import test_notification_config
from backend.routes_v2.settings_support.provider_test import test_provider


settings_v2_bp = Blueprint("settings_v2", __name__, url_prefix="/api/v2/settings")


@settings_v2_bp.get("")
def get_settings_v2():
    ctx = get_user_context()

    provider_service = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]
    destination_service = current_app.config["DESTINATION_CONFIG_SERVICE_V2"]

    providers = provider_service.list_provider_configs(ctx)
    destinations = destination_service.list_destination_configs(ctx)

    return jsonify({
        "providers": [serialize_provider(p) for p in providers],
        "destinations": [serialize_destination(d) for d in destinations],
    })


@settings_v2_bp.post("/provider/test")
def test_provider_v2():
    ctx = get_user_context()
    data = request.get_json(silent=True) or {}
    return test_provider(ctx, data)


@settings_v2_bp.post("/destination/test")
def test_destination_v2():
    ctx = get_user_context()
    data = request.get_json(silent=True) or {}
    return test_destination(ctx, data)


@settings_v2_bp.post("/notification/test")
def test_notification_config_v2():
    ctx = get_user_context()
    data = request.get_json(silent=True) or {}
    return test_notification_config(ctx, data)
