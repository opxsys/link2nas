from flask import Blueprint, current_app, jsonify

from backend.routes_v2.admin_users import require_super_admin


admin_cleanup_bp = Blueprint(
    "admin_cleanup_v2",
    __name__,
    url_prefix="/api/v2/admin/cleanup",
)


@admin_cleanup_bp.post("/run")
def run_cleanup():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["CLEANUP_SERVICE_V2"]
    result = service.run()

    return jsonify(result.to_dict())
from flask import Blueprint, current_app, jsonify

from backend.routes_v2.admin_users import require_super_admin


admin_cleanup_bp = Blueprint(
    "admin_cleanup_v2",
    __name__,
    url_prefix="/api/v2/admin/cleanup",
)


@admin_cleanup_bp.post("/run")
def run_cleanup():
    ctx, err = require_super_admin()
    if err:
        return err

    cleanup_service = current_app.config["CLEANUP_SERVICE_V2"]
    system_event_service = current_app.config.get("SYSTEM_EVENT_SERVICE_V2")

    try:
        result = cleanup_service.run()
    except Exception as exc:
        if system_event_service:
            system_event_service.create_for_super_admins(
                event_type="system.cleanup.failed",
                severity="critical",
                title="Cleanup failed",
                message=f"Cleanup failed: {exc}",
                component="cleanup",
                fingerprint="cleanup.exception",
                details={
                    "error": str(exc),
                },
            )

        return jsonify({
            "error": "Cleanup failed",
            "details": str(exc),
        }), 500

    result_dict = result.to_dict()
    temp_errors = result_dict.get("temp_files_errors") or []

    if temp_errors and system_event_service:
        system_event_service.create_for_super_admins(
            event_type="system.cleanup.failed",
            severity="warning",
            title="Cleanup completed with errors",
            message="Cleanup completed but some temporary files could not be deleted.",
            component="cleanup",
            fingerprint="cleanup.temp_files_errors",
            details=result_dict,
        )

    return jsonify(result_dict)