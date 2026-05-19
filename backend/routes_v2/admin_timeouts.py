from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.app_settings_service import AppSettingsValidationError


admin_timeouts_bp = Blueprint(
    "admin_timeouts_v2",
    __name__,
    url_prefix="/api/v2/admin/timeouts",
)


@admin_timeouts_bp.get("/restart-cooldowns")
def get_restart_cooldowns():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    return jsonify(service.get_restart_cooldowns())


@admin_timeouts_bp.put("/restart-cooldowns")
def save_restart_cooldowns():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    payload = request.get_json(silent=True) or {}

    try:
        result = service.save_restart_cooldowns(payload)
    except AppSettingsValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)
