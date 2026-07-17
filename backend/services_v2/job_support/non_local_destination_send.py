from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.job_support.notifications import emit_notification_event


def send_to_non_local_destination_impl(
    service,
    job: "Job",
    resolved,
    output_links: list[dict],
    previous_status: str,
) -> "Job":
    result = resolved.destination.send(output_links) or {}

    latest = service.job_repository.get_by_id(job.user_id, job.id)
    if latest is None:
        return None
    job = latest

    job.status = "completed"
    job.sent_to_destination = True
    job.sent_to_destination_at = now()
    job.destination_status = "sent"
    job.destination_message = "Sent to destination"
    job.destination_message_key = "destination.message.sent"
    job.destination_message_params = None
    job.destination_path = result.get("destination_path") or job.destination_path
    job.completed_at = job.completed_at or now()
    job.updated_at = now()
    job.error_message = None

    service.job_repository.update_destination_state(job)

    emit_notification_event(
        service.notification_service,
        job,
        event_type="destination.sent",
        severity="info",
        title="Destination sent",
        message="Job was sent to destination.",
    )

    if previous_status != "completed":
        emit_notification_event(
            service.notification_service,
            job,
            event_type="job.completed",
            severity="info",
            title="Job completed",
            message="Job completed successfully.",
        )

    return job
