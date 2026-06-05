from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2._context import get_user_context
from backend.services_v2.announcement_service import AnnouncementEmailUnavailableError
from backend.services_v2.app_settings_support.validation import AppSettingsValidationError


admin_announcements_bp = Blueprint(
    "admin_announcements_v2", __name__, url_prefix="/api/v2/admin/announcements"
)


def _require_admin():
    ctx = get_user_context()
    if ctx.role != "super_admin":
        return None, (jsonify({"error": "Forbidden"}), 403)
    return ctx, None


def _service():
    return current_app.config["ANNOUNCEMENT_SERVICE_V2"]


@admin_announcements_bp.get("")
def list_announcements():
    _, err = _require_admin()
    if err:
        return err
    return jsonify(_service().list_admin())


@admin_announcements_bp.post("")
def create_announcement():
    ctx, err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        result = _service().create(data, ctx.user_id)
    except AnnouncementEmailUnavailableError as exc:
        return jsonify({"error": str(exc)}), 503
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(result), 201


@admin_announcements_bp.get("/<announcement_id>")
def get_announcement(announcement_id):
    _, err = _require_admin()
    if err:
        return err
    result = _service().get_admin(announcement_id)
    if result is None:
        return jsonify({"error": "Announcement not found"}), 404
    return jsonify(result)


@admin_announcements_bp.patch("/<announcement_id>")
def update_announcement(announcement_id):
    _, err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        result = _service().update(announcement_id, data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if result is None:
        return jsonify({"error": "Announcement not found"}), 404
    return jsonify(result)


@admin_announcements_bp.delete("/<announcement_id>")
def delete_announcement(announcement_id):
    _, err = _require_admin()
    if err:
        return err
    ok = _service().soft_delete(announcement_id)
    if not ok:
        return jsonify({"error": "Announcement not found"}), 404
    return "", 204


@admin_announcements_bp.get("/<announcement_id>/tracking")
def get_tracking(announcement_id):
    _, err = _require_admin()
    if err:
        return err
    result = _service().get_tracking(announcement_id)
    if result is None:
        return jsonify({"error": "Announcement not found"}), 404
    return jsonify(result)


@admin_announcements_bp.get("/settings")
def get_settings():
    _, err = _require_admin()
    if err:
        return err
    app_settings = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    if not app_settings:
        return jsonify({"enabled": True})
    return jsonify(app_settings.get_announcements_settings())


@admin_announcements_bp.put("/settings")
def save_settings():
    _, err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    app_settings = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    if not app_settings:
        return jsonify({"enabled": True})
    try:
        result = app_settings.save_announcements_settings(data)
    except AppSettingsValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(result)
