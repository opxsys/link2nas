from __future__ import annotations

import logging
import time

from app import create_app
from backend.services_v2.user_context import UserContext

logger = logging.getLogger(__name__)

REFRESH_STATUSES = {
    "started",
    "source_added",
    "waiting_files_selection",
    "downloading",
}

UNRESTRICT_STATUSES = {
    "downloaded",
}

DESTINATION_STATUSES = {
    "ready",
    "partially_ready",
}

def _emit_system_event(app, *, event_type: str, severity: str, title: str, message: str, component: str, fingerprint: str, details: dict | None = None) -> None:
    try:
        with app.app_context():
            system_event_service = app.config.get("SYSTEM_EVENT_SERVICE_V2")
            if not system_event_service:
                return

            system_event_service.create_for_super_admins(
                event_type=event_type,
                severity=severity,
                title=title,
                message=message,
                component=component,
                fingerprint=fingerprint,
                details=details or {},
            )
    except Exception:
        logger.exception("[V2_SYSTEM_EVENT_EMIT_ERROR] type=%s", event_type)


def _emit_scheduler_failed(app, *, error: str, details: dict | None = None) -> None:
    payload = {
        "error": error,
    }

    if details:
        payload.update(details)

    _emit_system_event(
        app,
        event_type="system.scheduler.failed",
        severity="error",
        title="Scheduler failed",
        message=f"Scheduler failed: {error}",
        component="scheduler",
        fingerprint="scheduler.exception",
        details=payload,
    )

def _run_jobs_once(app, orchestrator_settings: dict) -> dict:
    result = {
        "processed": 0,
        "refreshed": 0,
        "unrestricted": 0,
        "sent_to_destination": 0,
        "skipped": 0,
        "errors": 0,
    }

    if not bool(orchestrator_settings.get("enabled", True)):
        return result

    max_jobs = int(orchestrator_settings.get("max_jobs_per_run") or 25)
    auto_refresh = bool(orchestrator_settings.get("auto_refresh_enabled", True))
    auto_unrestrict = bool(orchestrator_settings.get("auto_unrestrict_enabled", True))
    auto_send_destination = bool(orchestrator_settings.get("auto_send_destination_enabled", True))

    with app.app_context():
        job_repository = app.config["JOB_REPOSITORY_V2"]
        job_service = app.config["JOB_SERVICE_V2"]

        jobs = job_repository.list_runnable_for_scheduler()

        for job in jobs[:max_jobs]:
            result["processed"] += 1

            ctx = UserContext(user_id=job.user_id, role="user")
            status = str(job.status or "").strip().lower()

            try:
                if status in REFRESH_STATUSES:
                    if not auto_refresh:
                        result["skipped"] += 1
                        continue

                    logger.info("[V2_SCHEDULER_REFRESH] job_id=%s status=%s", job.id, status)
                    job_service.refresh_job(ctx, job.id)
                    result["refreshed"] += 1
                    continue

                if status in UNRESTRICT_STATUSES:
                    if not auto_unrestrict:
                        result["skipped"] += 1
                        continue

                    logger.info("[V2_SCHEDULER_UNRESTRICT] job_id=%s", job.id)
                    job_service.unrestrict_job(ctx, job.id)
                    result["unrestricted"] += 1
                    continue

                destination_status = str(job.destination_status or "").strip().lower()

                if (
                    status in DESTINATION_STATUSES
                    and job.send_to_destination
                    and not job.sent_to_destination
                    and destination_status not in {
                        "queued",
                        "sending",
                        "downloading",
                        "sent",
                        "cancel_requested",
                        "cancelled",
                        "failed",
                    }
                ):
                    if not auto_send_destination:
                        result["skipped"] += 1
                        continue

                    logger.info("[V2_SCHEDULER_SEND_DESTINATION] job_id=%s", job.id)
                    job_service.send_to_destination(ctx, job.id)
                    result["sent_to_destination"] += 1
                    continue

                result["skipped"] += 1

            except Exception as exc:
                result["errors"] += 1
                logger.exception("[V2_SCHEDULER_ERROR] job_id=%s status=%s", job.id, status)

                _emit_scheduler_failed(
                    app,
                    error=str(exc),
                    details={
                        "phase": "jobs_orchestrator",
                        "job_id": job.id,
                        "job_status": status,
                    },
                )

    return result


def _run_notifications_once(app, dispatcher_settings: dict) -> dict | None:
    if not bool(dispatcher_settings.get("enabled", True)):
        return None

    limit = int(dispatcher_settings.get("limit") or 25)

    with app.app_context():
        dispatcher = app.config.get("NOTIFICATION_DISPATCHER_SERVICE_V2")
        if not dispatcher:
            logger.warning("[V2_NOTIFICATION_DISPATCHER_MISSING]")
            return None

        result = dispatcher.run_once_all_users(limit=limit)

        app_settings_service = app.config.get("APP_SETTINGS_SERVICE_V2")
        if app_settings_service:
            app_settings_service.save_notification_dispatcher_runtime(
                result,
                last_error=None if not result.get("errors") else str(result["errors"][-1].get("error")),
            )
        logger.info(
            "[V2_NOTIFICATION_DISPATCHER] processed=%s sent=%s retrying=%s failed=%s skipped=%s users=%s",
            result.get("processed", 0),
            result.get("sent", 0),
            result.get("retrying", 0),
            result.get("failed", 0),
            result.get("skipped", 0),
            result.get("users_processed", 0),
        )

        return result


def _get_runtime_settings(app) -> dict:
    with app.app_context():
        service = app.config["APP_SETTINGS_SERVICE_V2"]
        return service.get_runtime_settings()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    app = create_app()

    logger.info("[V2_SCHEDULER_START]")

    last_jobs_run = 0.0
    last_notifications_run = 0.0

    while True:
        loop_started = time.monotonic()

        try:
            runtime_settings = _get_runtime_settings(app)
        except Exception as exc:
            logger.exception("[V2_SCHEDULER_RUNTIME_SETTINGS_ERROR]")

            _emit_scheduler_failed(
                app,
                error=str(exc),
                details={
                    "phase": "runtime_settings",
                },
            )

            time.sleep(5)
            continue

        orchestrator_settings = (
            runtime_settings.get("jobs", {}).get("orchestrator", {})
        )
        dispatcher_settings = (
            runtime_settings.get("notifications", {}).get("dispatcher", {})
        )

        jobs_interval = int(orchestrator_settings.get("interval_seconds") or 5)
        notifications_interval = int(dispatcher_settings.get("interval_seconds") or 60)

        now_monotonic = time.monotonic()

        if now_monotonic - last_jobs_run >= jobs_interval:
            jobs_result = _run_jobs_once(app, orchestrator_settings)
            logger.info(
                "[V2_JOBS_ORCHESTRATOR] processed=%s refreshed=%s unrestricted=%s sent_destination=%s skipped=%s errors=%s",
                jobs_result.get("processed", 0),
                jobs_result.get("refreshed", 0),
                jobs_result.get("unrestricted", 0),
                jobs_result.get("sent_to_destination", 0),
                jobs_result.get("skipped", 0),
                jobs_result.get("errors", 0),
            )
            last_jobs_run = now_monotonic

        now_monotonic = time.monotonic()

        if now_monotonic - last_notifications_run >= notifications_interval:
            try:
                _run_notifications_once(app, dispatcher_settings)
            except Exception as exc:
                logger.exception("[V2_NOTIFICATION_DISPATCHER_ERROR]")

                with app.app_context():
                    app_settings_service = app.config.get("APP_SETTINGS_SERVICE_V2")
                    if app_settings_service:
                        app_settings_service.save_notification_dispatcher_runtime(
                            {
                                "finished_at": None,
                                "errors": [{"error": str(exc)}],
                            },
                            last_error=str(exc),
                        )

                _emit_system_event(
                    app,
                    event_type="system.notification_dispatcher.failed",
                    severity="error",
                    title="Notification dispatcher failed",
                    message=f"Notification dispatcher failed: {exc}",
                    component="notification_dispatcher",
                    fingerprint="notification_dispatcher.exception",
                    details={
                        "phase": "scheduler_notification_dispatcher",
                        "error": str(exc),
                    },
                )
            last_notifications_run = now_monotonic

        elapsed = time.monotonic() - loop_started
        time.sleep(max(1.0, 1.0 - elapsed))


if __name__ == "__main__":
    main()