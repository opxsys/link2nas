import json

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.job_support.notifications import emit_notification_event


def set_started_provider_job(
    job_repository,
    notification_service,
    job: Job,
    result: dict,
) -> Job:
    timestamp = now()

    job.provider_resource_id = str(result.get("id")) if result.get("id") else None
    job.provider_status = "submitted"
    job.provider_payload_json = json.dumps(result)
    job.status = "started"
    job.started_at = timestamp
    job.updated_at = timestamp
    job.error_message = None

    job_repository.update_provider_state(job)

    emit_notification_event(
        notification_service,
        job,
        event_type="job.started",
        severity="info",
        title="Job started",
        message="Job has started.",
    )

    return job
