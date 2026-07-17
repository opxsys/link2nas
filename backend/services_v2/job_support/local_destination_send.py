from flask import current_app

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext


def send_to_local_destination_impl(
    service,
    context: UserContext,
    job: "Job",
    resolved,
    output_links: list[dict],
) -> "Job":
    settings = current_app.config["SETTINGS"]

    current_status = str(job.destination_status or "").strip().lower()

    if current_status in {"queued", "downloading", "cancel_requested"}:
        return job

    resolved.destination.ensure_enough_space(
        output_links,
        margin_percent=settings.LOCAL_DOWNLOAD_SPACE_MARGIN_PERCENT,
        min_free_bytes=settings.LOCAL_DOWNLOAD_MIN_FREE_BYTES,
    )

    job.destination_status = "queued"
    job.destination_message = "Local download queued"
    job.destination_message_key = "destination.message.local.queued"
    job.destination_message_params = None
    job.sent_to_destination = False
    job.sent_to_destination_at = None
    job.destination_last_attempt = now()
    job.error_message = None
    job.updated_at = now()

    service.job_repository.update_unrestrict_state(job)
    service.job_repository.update_destination_state(job)

    job = service.get_job(context, job.id)
    if job is None:
        return None

    service._enqueue_local_download(
        context=context,
        job=job,
        destination_config_id=resolved.destination_config_id,
    )

    return job
