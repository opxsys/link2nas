import json

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.job_support.notifications import emit_notification_event, emit_provider_failed


def start_direct_link_job(
    job_repository,
    notification_service,
    provider,
    job: Job,
) -> Job:
    try:
        result = provider.unrestrict_link(job.source_value)
    except Exception as exc:
        emit_provider_failed(notification_service, job, exc)
        raise

    download_url = result.get("download")

    if not download_url:
        raise ValueError("Provider returned no download URL")

    output_links = [
        {
            "url": download_url,
            "filename": result.get("filename"),
            "filesize": result.get("filesize"),
            "provider_download_id": result.get("id"),
            "relative_path": result.get("filename"),
            "path": result.get("filename"),
        }
    ]

    timestamp = now()

    job.provider_status = "unrestricted"
    job.provider_payload_json = json.dumps(result)
    job.output_mode = "single"
    job.output_links_json = json.dumps(output_links)
    job.status = "ready"
    job.started_at = timestamp
    job.unrestricted_at = timestamp
    job.updated_at = timestamp
    job.error_message = None

    job_repository.update_provider_state(job)
    job_repository.update_unrestrict_state(job)

    emit_notification_event(
        notification_service,
        job,
        event_type="job.started",
        severity="info",
        title="Job started",
        message="Job has started.",
    )

    emit_notification_event(
        notification_service,
        job,
        event_type="job.ready",
        severity="info",
        title="Job ready",
        message="Job direct link is ready.",
    )

    emit_notification_event(
        notification_service,
        job,
        event_type="job.links_ready",
        severity="info",
        title="Links ready",
        message="Direct links are available for this job.",
    )

    return job
