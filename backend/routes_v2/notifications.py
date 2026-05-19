from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2._context import get_user_context
from backend.services_v2.notification_service import (
    NotificationNotFoundError,
    NotificationValidationError,
)


notifications_v2_bp = Blueprint(
    "notifications_v2",
    __name__,
    url_prefix="/api/v2/notifications",
)


def _service():
    return current_app.config["NOTIFICATION_SERVICE_V2"]


def _handle_validation_error(exc):
    return jsonify({"error": str(exc)}), 400


def _handle_not_found_error(exc):
    return jsonify({"error": str(exc)}), 404


# -------------------------------------------------------------------------
# Configs = endpoints / channels
# -------------------------------------------------------------------------


@notifications_v2_bp.get("/configs")
def list_notification_configs():
    ctx = get_user_context()
    return jsonify(_service().list_configs(ctx.user_id))


@notifications_v2_bp.post("/configs")
def create_notification_config():
    ctx = get_user_context()
    payload = request.get_json(silent=True) or {}

    try:
        created = _service().create_config(ctx.user_id, payload)
    except NotificationValidationError as exc:
        return _handle_validation_error(exc)

    return jsonify(created), 201


@notifications_v2_bp.get("/configs/<config_id>")
def get_notification_config(config_id: str):
    ctx = get_user_context()

    try:
        item = _service().get_config(ctx.user_id, config_id)
    except NotificationNotFoundError as exc:
        return _handle_not_found_error(exc)

    return jsonify(item)


@notifications_v2_bp.put("/configs/<config_id>")
def update_notification_config(config_id: str):
    ctx = get_user_context()
    payload = request.get_json(silent=True) or {}

    try:
        updated = _service().update_config(ctx.user_id, config_id, payload)
    except NotificationValidationError as exc:
        return _handle_validation_error(exc)
    except NotificationNotFoundError as exc:
        return _handle_not_found_error(exc)

    return jsonify(updated)


@notifications_v2_bp.delete("/configs/<config_id>")
def delete_notification_config(config_id: str):
    ctx = get_user_context()

    deleted = _service().delete_config(ctx.user_id, config_id)

    if not deleted:
        return jsonify({"error": "Notification config not found"}), 404

    return jsonify({"deleted": True})

@notifications_v2_bp.post("/configs/<config_id>/test")
def test_notification_config(config_id: str):
    ctx = get_user_context()

    try:
        result = _service().test_config(ctx.user_id, config_id)
    except NotificationValidationError as exc:
        return _handle_validation_error(exc)
    except NotificationNotFoundError as exc:
        return _handle_not_found_error(exc)

    return jsonify(result)

# -------------------------------------------------------------------------
# Rules = subscriptions
# -------------------------------------------------------------------------


@notifications_v2_bp.get("/rules")
def list_notification_rules():
    ctx = get_user_context()
    return jsonify(_service().list_rules(ctx.user_id))


@notifications_v2_bp.post("/rules")
def create_notification_rule():
    ctx = get_user_context()
    payload = request.get_json(silent=True) or {}

    try:
        created = _service().create_rule(ctx.user_id, payload)
    except NotificationValidationError as exc:
        return _handle_validation_error(exc)

    return jsonify(created), 201


@notifications_v2_bp.get("/rules/<rule_id>")
def get_notification_rule(rule_id: str):
    ctx = get_user_context()

    try:
        item = _service().get_rule(ctx.user_id, rule_id)
    except NotificationNotFoundError as exc:
        return _handle_not_found_error(exc)

    return jsonify(item)


@notifications_v2_bp.put("/rules/<rule_id>")
def update_notification_rule(rule_id: str):
    ctx = get_user_context()
    payload = request.get_json(silent=True) or {}

    try:
        updated = _service().update_rule(ctx.user_id, rule_id, payload)
    except NotificationValidationError as exc:
        return _handle_validation_error(exc)
    except NotificationNotFoundError as exc:
        return _handle_not_found_error(exc)

    return jsonify(updated)


@notifications_v2_bp.delete("/rules/<rule_id>")
def delete_notification_rule(rule_id: str):
    ctx = get_user_context()

    deleted = _service().delete_rule(ctx.user_id, rule_id)

    if not deleted:
        return jsonify({"error": "Notification rule not found"}), 404

    return jsonify({"deleted": True})


# -------------------------------------------------------------------------
# Events
# -------------------------------------------------------------------------


@notifications_v2_bp.get("/events")
def list_notification_events():
    ctx = get_user_context()

    raw_limit = request.args.get("limit", "50")

    try:
        limit = int(raw_limit)
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400

    if limit < 1:
        return jsonify({"error": "limit must be >= 1"}), 400

    if limit > 200:
        return jsonify({"error": "limit must be <= 200"}), 400

    return jsonify(_service().list_events(ctx.user_id, limit=limit))