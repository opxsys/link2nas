from flask import Blueprint, current_app, jsonify, request
from backend.services_v2.notification_service import NotificationValidationError
from backend.routes_v2._context import get_user_context


admin_notifications_bp = Blueprint(
    "admin_notifications_v2",
    __name__,
    url_prefix="/api/v2/admin/notifications",
)


def _dispatcher():
    return current_app.config["NOTIFICATION_DISPATCHER_SERVICE_V2"]

def _forbidden_response(exc):
    return jsonify({"error": str(exc)}), 403
    
def _require_super_admin(ctx) -> None:
    user_repo = current_app.config["USER_REPO_V2"]
    user = user_repo.get_by_id(ctx.user_id)

    if not user or getattr(user, "role", None) != "super_admin":
        raise PermissionError("Super admin required")

@admin_notifications_bp.get("/dispatcher/status")
def dispatcher_status():
    ctx = get_user_context()
    try:
        _require_super_admin(ctx)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403

    dispatcher = current_app.config.get("NOTIFICATION_DISPATCHER_SERVICE_V2")
    app_settings_service = current_app.config.get("APP_SETTINGS_SERVICE_V2")

    status = dispatcher.get_status(ctx.user_id) if dispatcher else {
        "enabled": False,
        "last_run_at": None,
        "last_error": "Notification dispatcher service not configured",
        "last_result": None,
        "message": "Notification dispatcher unavailable",
    }

    if app_settings_service:
        runtime_settings = app_settings_service.get_runtime_settings()
        persisted = runtime_settings.get("notifications", {}).get("dispatcher", {})

        status["enabled"] = bool(persisted.get("enabled", status.get("enabled", True)))
        status["last_run_at"] = persisted.get("last_run_at")
        status["last_error"] = persisted.get("last_error")
        status["last_result"] = persisted.get("last_result")

    return jsonify(status)

@admin_notifications_bp.post("/dispatcher/run-once")
def run_dispatcher_once():
    ctx = get_user_context()

    try:
        _require_super_admin(ctx)
    except PermissionError as exc:
        return _forbidden_response(exc)

    payload = request.get_json(silent=True) or {}

    user_id = str(payload.get("user_id") or ctx.user_id).strip()
    limit = int(payload.get("limit") or 25)

    if limit < 1:
        return jsonify({"error": "limit must be >= 1"}), 400

    if limit > 200:
        return jsonify({"error": "limit must be <= 200"}), 400

    system_event_service = current_app.config.get("SYSTEM_EVENT_SERVICE_V2")

    try:
        result = _dispatcher().run_once_for_user(
            user_id=user_id,
            limit=limit,
        )
    except Exception as exc:
        if system_event_service:
            system_event_service.create_for_super_admins(
                event_type="system.notification_dispatcher.failed",
                severity="error",
                title="Notification dispatcher failed",
                message=f"Notification dispatcher failed: {exc}",
                component="notification_dispatcher",
                fingerprint="notification_dispatcher.exception",
                details={
                    "error": str(exc),
                    "route": "/api/v2/admin/notifications/dispatcher/run-once",
                    "user_id": user_id,
                    "limit": limit,
                },
            )

        return jsonify({
            "error": "Notification dispatcher failed",
            "details": str(exc),
        }), 500

    errors = result.get("errors") or []

    if errors and system_event_service:
        system_event_service.create_for_super_admins(
            event_type="system.notification_dispatcher.failed",
            severity="warning",
            title="Notification dispatcher completed with errors",
            message=f"Notification dispatcher completed with {len(errors)} error(s).",
            component="notification_dispatcher",
            fingerprint="notification_dispatcher.errors",
            details={
                "route": "/api/v2/admin/notifications/dispatcher/run-once",
                "user_id": user_id,
                "limit": limit,
                "result": result,
            },
        )

    return jsonify(result)

    return jsonify(result)
@admin_notifications_bp.post("/events/test")
def create_test_notification_event():
    ctx = get_user_context()

    try:
        _require_super_admin(ctx)
    except PermissionError as exc:
        return _forbidden_response(exc)

    payload = request.get_json(silent=True) or {}

    event_type = str(payload.get("type") or "job.failed").strip()
    severity = str(payload.get("severity") or "error").strip()
    title = str(payload.get("title") or "Test notification event").strip()
    message = str(payload.get("message") or "Test notification message").strip()
    job_id = payload.get("job_id")

    service = current_app.config["NOTIFICATION_SERVICE_V2"]

    event = service.create_event(
        user_id=ctx.user_id,
        type=event_type,
        severity=severity,
        title=title,
        message=message,
        job_id=job_id,
        payload={
            "source": "admin_test",
            "job_id": job_id,
        },
    )

    return jsonify(event)

@admin_notifications_bp.get("/events")
def list_all_notification_events():
    ctx = get_user_context()
    try:
        _require_super_admin(ctx)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403

    service = current_app.config["NOTIFICATION_SERVICE_V2"]

    try:
        limit = int(request.args.get("limit", 100))
    except Exception:
        return jsonify({"error": "limit must be an integer"}), 400

    status = request.args.get("status")

    try:
        events = service.list_all_events_admin(
            limit=limit,
            status=status,
        )
    except NotificationValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(events)