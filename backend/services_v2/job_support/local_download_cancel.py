from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.notifications import emit_notification_event


def cancel_local_download_impl(
    service,
    context: UserContext,
    job_id: str,
) -> "Job | None":
    job = service.get_job(context, job_id)

    if job is None:
        return None

    if job.destination_name != "local":
        raise ValueError("Only local destination downloads can be cancelled")

    current_status = str(job.destination_status or "").strip().lower()

    if current_status not in {"queued", "sending", "downloading"}:
        raise ValueError("Local download is not running or queued")

    job.destination_status = "cancel_requested"
    job.destination_message = "Local download cancellation requested"
    job.send_to_destination = False
    job.sent_to_destination = False
    job.destination_progress = 0
    job.updated_at = now()

    service.job_repository.update_destination_state(job)

    emit_notification_event(
        service.notification_service,
        job,
        event_type="destination.cancelled",
        severity="warning",
        title="Destination cancelled",
        message="Local destination download cancellation requested.",
    )

    return job
