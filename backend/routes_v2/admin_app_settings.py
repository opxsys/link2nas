from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.app_settings_service import AppSettingsValidationError


admin_app_settings_bp = Blueprint(
    "admin_app_settings_v2",
    __name__,
    url_prefix="/api/v2/admin/app-settings",
)


@admin_app_settings_bp.get("/security")
def get_security_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    return jsonify(service.get_security_settings())


@admin_app_settings_bp.put("/security")
def save_security_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    payload = request.get_json(silent=True) or {}

    try:
        result = service.save_security_settings(payload)
    except AppSettingsValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


@admin_app_settings_bp.get("/cleanup")
def get_cleanup_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    return jsonify(service.get_cleanup_settings())

@admin_app_settings_bp.get("/system-events")
def get_system_events_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    return jsonify(service.get_system_events_settings())


@admin_app_settings_bp.put("/system-events")
def save_system_events_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    payload = request.get_json(silent=True) or {}

    try:
        result = service.save_system_events_settings(payload)
    except AppSettingsValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)

@admin_app_settings_bp.put("/cleanup")
def save_cleanup_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    payload = request.get_json(silent=True) or {}

    try:
        result = service.save_cleanup_settings(payload)
    except AppSettingsValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)

@admin_app_settings_bp.get("/runtime")
def get_runtime_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    dispatcher = current_app.config.get("NOTIFICATION_DISPATCHER_SERVICE_V2")

    result = service.get_runtime_settings()

    if dispatcher:
        dispatcher_status = dispatcher.get_status()
        result["notifications"]["dispatcher"]["last_run_at"] = dispatcher_status.get("last_run_at")
        result["notifications"]["dispatcher"]["last_result"] = dispatcher_status.get("last_result")
        result["notifications"]["dispatcher"]["last_error"] = dispatcher_status.get("last_error")

    return jsonify(result)


@admin_app_settings_bp.put("/runtime")
def save_runtime_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    payload = request.get_json(silent=True) or {}

    try:
        result = service.save_runtime_settings(payload)
    except AppSettingsValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


@admin_app_settings_bp.get("/general")
def get_general_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    settings = current_app.config.get("SETTINGS")

    return jsonify(service.get_general_settings(
        env_name=getattr(settings, "APP_NAME", ""),
        env_tagline=getattr(settings, "APP_TAGLINE", ""),
        env_url=getattr(settings, "PUBLIC_BASE_URL", ""),
    ))


@admin_app_settings_bp.put("/general")
def save_general_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["APP_SETTINGS_SERVICE_V2"]
    settings = current_app.config.get("SETTINGS")
    payload = request.get_json(silent=True) or {}

    try:
        result = service.save_general_settings(
            payload,
            env_name=getattr(settings, "APP_NAME", ""),
            env_tagline=getattr(settings, "APP_TAGLINE", ""),
            env_url=getattr(settings, "PUBLIC_BASE_URL", ""),
        )
    except AppSettingsValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)