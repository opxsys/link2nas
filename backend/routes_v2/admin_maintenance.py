from flask import Blueprint, current_app, jsonify

from backend.routes_v2.admin_users import require_super_admin


admin_maintenance_bp = Blueprint(
    "admin_maintenance_v2",
    __name__,
    url_prefix="/api/v2/admin/maintenance",
)


def _emit_maintenance_system_events(status: dict) -> None:
    system_event_service = current_app.config.get("SYSTEM_EVENT_SERVICE_V2")
    if not system_event_service:
        return

    database = status.get("database") or {}
    disk = status.get("disk") or {}
    paths = status.get("paths") or []

    failed_paths = [
        item for item in paths
        if item.get("required") and not item.get("ok")
    ]

    database_failed = not bool(database.get("ok"))
    paths_failed = bool(failed_paths)
    maintenance_failed = not bool(status.get("ok"))

    if maintenance_failed:
        details = {
            "generated_at": status.get("generated_at"),
            "database": database,
            "failed_paths": failed_paths,
            "disk": disk,
        }

        reasons = []

        if database_failed:
            reasons.append("database")

        if paths_failed:
            reasons.append("paths")

        if not reasons:
            reasons.append("unknown")

        system_event_service.create_for_super_admins(
            event_type="system.maintenance.failed",
            severity="error",
            title="Maintenance health check failed",
            message=f"Maintenance health check failed: {', '.join(reasons)}",
            component="maintenance",
            fingerprint="maintenance.failed." + ".".join(sorted(reasons)),
            details=details,
        )

    try:
        percent_free = float(disk.get("percent_free") or 0)
    except Exception:
        percent_free = 0

    if percent_free < 5:
        severity = "critical"
    elif percent_free < 10:
        severity = "warning"
    else:
        severity = None

    if severity:
        system_event_service.create_for_super_admins(
            event_type="system.storage.low",
            severity=severity,
            title="Storage space low",
            message=f"Storage space is low: {percent_free}% free",
            component="storage",
            fingerprint=f"storage.low.{severity}",
            details={
                "generated_at": status.get("generated_at"),
                "disk": disk,
            },
        )


@admin_maintenance_bp.get("/status")
def get_maintenance_status():
    ctx, err = require_super_admin()
    if err:
        return err

    service = current_app.config["MAINTENANCE_SERVICE_V2"]
    status = service.get_status()

    _emit_maintenance_system_events(status)

    return jsonify(status)