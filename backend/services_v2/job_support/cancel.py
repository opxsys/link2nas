from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.notifications import emit_notification_event


def cancel_job_impl(
    service,
    context: UserContext,
    job_id: str,
) -> "Job | None":
    job = service.get_job(context, job_id)

    if job is None:
        return None

    service._ensure_action_allowed(job, "cancel")

    try:
        service._delete_provider_resources_best_effort(context, job)
    except Exception as exc:
        job.error_message = str(exc)
        job.updated_at = now()
        service.job_repository.update_status_state(job)
        raise

    timestamp = now()

    job.status = "cancelled"
    job.error_message = None
    job.updated_at = timestamp
    job.completed_at = timestamp
    job.cancelled_at = timestamp

    job.provider_resource_id = None
    job.provider_status = None
    job.provider_payload_json = None

    job.output_mode = None
    job.output_links_json = None
    job.unrestricted_at = None

    job.sent_to_destination = False
    job.sent_to_destination_at = None
    job.destination_status = "pending" if job.send_to_destination else None
    job.destination_message = None
    job.destination_message_key = None
    job.destination_message_params = None
    job.destination_last_attempt = None
    job.destination_path = None

    service.job_repository.update_full_reset(job)

    emit_notification_event(
        service.notification_service,
        job,
        event_type="job.cancelled",
        severity="warning",
        title="Job cancelled",
        message="Job was cancelled.",
    )

    return job
