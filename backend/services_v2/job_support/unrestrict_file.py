import json

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.source_helpers import filename_from_path
from backend.services_v2.job_support.notifications import emit_notification_event


def unrestrict_file_impl(
    service,
    context: UserContext,
    job_id: str,
    file_id: int,
) -> "Job | None":
    job = service.get_job(context, job_id)

    if job is None:
        return None

    payload = json.loads(job.provider_payload_json or "{}")
    links = payload.get("links") or []
    files = payload.get("files") or []

    index = int(file_id) - 1

    if index < 0 or index >= len(links):
        raise ValueError("Invalid file id")

    if service.provider_factory is None:
        raise RuntimeError("Provider factory is not configured")

    provider = service.provider_factory.get_provider_for_user(
        user_id=context.user_id,
        provider_config_id=job.provider_config_id,
        provider_name=job.provider_name,
    )

    existing_links = json.loads(job.output_links_json or "[]")
    if not isinstance(existing_links, list):
        existing_links = []

    while len(existing_links) < len(links):
        existing_links.append({})

    link = links[index]
    file_meta = files[index] if index < len(files) and isinstance(files[index], dict) else {}

    try:
        result = provider.unrestrict_link(link)
    except Exception as exc:
        service._emit_provider_failed(job, exc)
        raise

    download_url = result.get("download")

    if not download_url:
        raise ValueError("Provider returned no download URL")

    relative_path = file_meta.get("path") or result.get("filename")
    filename = result.get("filename") or filename_from_path(relative_path)

    had_links = any(item for item in existing_links if item)

    existing_links[index] = {
        "url": download_url,
        "filename": filename,
        "filesize": result.get("filesize") or file_meta.get("bytes"),
        "provider_download_id": result.get("id"),
        "debrid_link": link,
        "file_id": file_meta.get("id") or file_id,
        "relative_path": relative_path,
        "path": relative_path,
    }

    previous_status = str(job.status or "").strip().lower()
    compact_links = [item for item in existing_links if item]

    job.output_mode = "single" if len(compact_links) == 1 else "per_file"
    job.output_links_json = json.dumps(compact_links)
    job.status = "ready" if job.status != "completed" else "completed"
    job.unrestricted_at = now()
    job.updated_at = now()
    job.error_message = None

    service.job_repository.update_unrestrict_state(job)

    if previous_status != "ready" and job.status == "ready":
        emit_notification_event(
            service.notification_service,
            job,
            event_type="job.ready",
            severity="info",
            title="Job ready",
            message="Job direct links are ready.",
        )

    if compact_links and not had_links:
        emit_notification_event(
            service.notification_service,
            job,
            event_type="job.links_ready",
            severity="info",
            title="Links ready",
            message="Direct links are available for this job.",
        )

    return job
