import logging

from flask import current_app
from rq import cancel_job

from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.redis_connection import build_redis_connection
from backend.services_v2.job_support.local_download_queue import local_download_task_id

logger = logging.getLogger(__name__)


def delete_job_impl(
    service,
    context: UserContext,
    job_id: str,
) -> bool:
    job = service.get_job(context, job_id)

    if job is None:
        return False

    try:
        service._delete_provider_resources_best_effort(context, job)
    except Exception:
        pass

    try:
        settings = current_app.config["SETTINGS"]
        cancel_job(
            local_download_task_id(context.user_id, job_id),
            connection=build_redis_connection(settings, decode_responses=False),
            enqueue_dependents=False,
        )
    except Exception as exc:
        # Database deletion is authoritative; stale workers re-check the job.
        logger.info("Unable to cancel queued local download job_id=%s error_type=%s", job_id, type(exc).__name__)

    service.job_repository.delete(context.user_id, job_id)
    return True
