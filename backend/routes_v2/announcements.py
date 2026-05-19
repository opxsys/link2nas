from flask import Blueprint, current_app, jsonify

from backend.routes_v2._context import get_user_context


announcements_v2_bp = Blueprint("announcements_v2", __name__, url_prefix="/api/v2")


def _service():
    return current_app.config["ANNOUNCEMENT_SERVICE_V2"]


@announcements_v2_bp.get("/announcements/active")
def list_active_announcements():
    ctx = get_user_context()
    return jsonify(_service().list_active(ctx.user_id))


@announcements_v2_bp.get("/announcements")
def list_announcements():
    ctx = get_user_context()
    return jsonify(_service().list_all_with_user_status(ctx.user_id))


@announcements_v2_bp.post("/announcements/<announcement_id>/open")
def open_announcement(announcement_id):
    ctx = get_user_context()
    ok = _service().mark_opened(announcement_id, ctx.user_id)
    if not ok:
        return jsonify({"error": "Announcement not found"}), 404
    return jsonify({"ok": True})


@announcements_v2_bp.post("/announcements/<announcement_id>/read")
def read_announcement(announcement_id):
    ctx = get_user_context()
    ok = _service().mark_read(announcement_id, ctx.user_id)
    if not ok:
        return jsonify({"error": "Announcement not found"}), 404
    return jsonify({"ok": True})


@announcements_v2_bp.post("/announcements/<announcement_id>/acknowledge")
def acknowledge_announcement(announcement_id):
    ctx = get_user_context()
    try:
        ok = _service().mark_acknowledged(announcement_id, ctx.user_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not ok:
        return jsonify({"error": "Announcement not found"}), 404
    return jsonify({"ok": True})
