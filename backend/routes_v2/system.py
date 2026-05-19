from backend.utils.time import utc_now_iso

from flask import Blueprint, current_app, jsonify
from redis import Redis
from rq import Queue, Worker

from backend.routes_v2._context import get_user_context


system_v2_bp = Blueprint("system_v2", __name__, url_prefix="/api/v2/system")


now = utc_now_iso


def _count_jobs_by_status(job_repository, user_id: str) -> dict:
    jobs = job_repository.list_for_user(user_id)
    counts = {}

    for job in jobs:
        status = str(job.status or "unknown").strip().lower()
        counts[status] = counts.get(status, 0) + 1

    return counts


def _count_active_jobs(job_repository, user_id: str) -> int:
    active_statuses = {
        "created",
        "queued",
        "started",
        "source_added",
        "waiting_files_selection",
        "downloading",
        "downloaded",
        "ready",
        "partially_ready",
    }

    jobs = job_repository.list_for_user(user_id)

    return sum(
        1
        for job in jobs
        if str(job.status or "").strip().lower() in active_statuses
    )


def _count_destination_pending(job_repository, user_id: str) -> int:
    jobs = job_repository.list_for_user(user_id)

    return sum(
        1
        for job in jobs
        if bool(getattr(job, "send_to_destination", False))
        and not bool(getattr(job, "sent_to_destination", False))
    )


def _get_default_provider_config(ctx):
    service = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]
    providers = service.list_provider_configs(ctx)

    enabled = [provider for provider in providers if provider.is_enabled]

    if not enabled:
        return None

    for provider in enabled:
        if provider.is_default:
            return provider

    return enabled[0]


def _get_default_destination_config(ctx):
    service = current_app.config["DESTINATION_CONFIG_SERVICE_V2"]
    destinations = service.list_destination_configs(ctx)

    enabled = [destination for destination in destinations if destination.is_enabled]

    if not enabled:
        return None

    for destination in enabled:
        if destination.is_default:
            return destination

    return enabled[0]


def _queue_info():
    settings = current_app.config["SETTINGS"]
    try:
        redis_conn = Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=False,
        )
        queue_names = [settings.RQ_QUEUE_NAME, settings.RQ_LOCAL_DOWNLOAD_QUEUE_NAME]
        queues = [Queue(name, connection=redis_conn) for name in queue_names]
        workers = Worker.all(connection=redis_conn)

        workers_busy = sum(1 for w in workers if w.state == "busy")
        return {
            "queue_name":      ", ".join(queue_names),
            "pending_count":   sum(q.count for q in queues),
            "started_count":   workers_busy,
            "failed_count":    sum(q.failed_job_registry.count for q in queues),
            "scheduled_count": sum(q.scheduled_job_registry.count for q in queues),
            "deferred_count":  0,
            "workers_total":   len(workers),
            "workers_busy":    workers_busy,
            "workers_idle":    len(workers) - workers_busy,
            "workers_names":   [w.name for w in workers],
        }
    except Exception as exc:
        return {
            "queue_name": "-",
            "pending_count": 0,
            "started_count": 0,
            "failed_count": 0,
            "scheduled_count": 0,
            "deferred_count": 0,
            "workers_total": 0,
            "workers_busy": 0,
            "workers_idle": 0,
            "workers_names": [],
            "message": str(exc),
        }


@system_v2_bp.get("/provider")
def get_v2_provider_status():
    ctx = get_user_context()

    provider = _get_default_provider_config(ctx)

    if not provider:
        return jsonify({
            "provider_config_id": None,
            "provider": None,
            "provider_type": None,
            "provider_profile_name": None,
            "username": "-",
            "email": "-",
            "premium": False,
            "type": "none",
            "expiration": None,
            "points": None,
            "locale": None,
            "message": "No provider configured",
        })

    return jsonify({
        "provider_config_id": provider.id,
        "provider": provider.provider_type,
        "provider_type": provider.provider_type,
        "provider_profile_name": provider.name,
        "username": "-",
        "email": "-",
        "premium": bool(provider.is_enabled),
        "type": "configured",
        "expiration": provider.account_expires_at,
        "points": None,
        "locale": None,
        "message": None,
    })


@system_v2_bp.get("/control-center")
def get_v2_control_center():
    ctx = get_user_context()

    job_repository = current_app.config["JOB_REPOSITORY_V2"]

    provider = _get_default_provider_config(ctx)
    destination = _get_default_destination_config(ctx)

    jobs = job_repository.list_for_user(ctx.user_id)
    status_counts = _count_jobs_by_status(job_repository, ctx.user_id)

    app_settings_service = current_app.config.get("APP_SETTINGS_SERVICE_V2")

    restart_cooldowns = {
        "default_seconds": 10,
        "realdebrid_seconds": 60,
        "alldebrid_seconds": 8,
    }

    if app_settings_service is not None:
        restart_cooldowns = app_settings_service.get_restart_cooldowns()

    return jsonify({
        "generated_at": now(),

        "provider_config_id": provider.id if provider else None,
        "provider": provider.provider_type if provider else None,
        "provider_type": provider.provider_type if provider else None,
        "provider_profile_name": provider.name if provider else None,

        "destination_config_id": destination.id if destination else None,
        "destination_type": destination.destination_type if destination else None,
        "destination_profile_name": destination.name if destination else None,

        "jobs_total": len(jobs),
        "jobs_active": _count_active_jobs(job_repository, ctx.user_id),
        "jobs_with_destination_pending": _count_destination_pending(job_repository, ctx.user_id),
        "status_counts": status_counts,

        "queue": _queue_info(),

        "restart_cooldowns": restart_cooldowns,
    })
