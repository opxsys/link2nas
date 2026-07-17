from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.task_guard import reload_job


def restart_job_impl(
    service,
    context: UserContext,
    job_id: str,
) -> "Job | None":
    job = service.get_job(context, job_id)

    if job is None:
        return None

    service._ensure_action_allowed(job, "restart")
    service._ensure_restart_cooldown_elapsed(job)

    job.status = "created"

    job.provider_resource_id = None
    job.provider_status = None
    job.provider_payload_json = None
    job.provider_error_fingerprint = None

    job.output_mode = None
    job.output_links_json = None
    job.unrestricted_at = None

    job.error_message = None

    job.started_at = None
    job.completed_at = None
    job.cancelled_at = None

    job.sent_to_destination = False
    job.sent_to_destination_at = None
    job.destination_status = "pending" if job.send_to_destination else None
    job.destination_message = None
    job.destination_message_key = None
    job.destination_message_params = None
    job.destination_last_attempt = None
    job.destination_path = None

    job.updated_at = now()

    service.job_repository.update_full_reset(job)

    if reload_job(service, context, job.id, task_type="provider_restart", require_active=True) is None:
        return None

    return service.start_job(context, job.id)
