import logging

logger = logging.getLogger(__name__)

TERMINAL_JOB_STATUSES = frozenset({"failed", "cancelled", "completed"})


def reload_job(service, context, job_id: str, *, task_type: str, require_active: bool = False):
    job = service.get_job(context, job_id)
    if job is None:
        logger.info("Ignoring task for deleted job %s task=%s", job_id, task_type)
        return None
    if require_active and str(job.status or "").strip().lower() in TERMINAL_JOB_STATUSES:
        logger.info("Skipping next task enqueue: job no longer active job_id=%s task=%s", job_id, task_type)
        return None
    return job
