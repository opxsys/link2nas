import json

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.notifications import emit_notification_event
from backend.services_v2.job_support.task_guard import reload_job


def unrestrict_job_impl(
    service,
    context: UserContext,
    job_id: str,
) -> "Job | None":
    job = reload_job(service, context, job_id, task_type="provider_unrestrict")

    if job is None:
        return None

    if job.status not in {"downloaded", "ready", "completed"}:
        service._ensure_action_allowed(job, "unrestrict")

    previous_status = str(job.status or "").strip().lower()
    had_links = bool(json.loads(job.output_links_json or "[]"))

    try:
        output_links = service._build_output_links(context, job)
    except Exception as exc:
        terminal = service._record_provider_failure(context, job, exc)
        if terminal or service.get_job(context, job_id) is None:
            return service.get_job(context, job_id)
        raise

    job = reload_job(service, context, job_id, task_type="provider_unrestrict_post_call")
    if job is None:
        return None

    job.output_mode = "single" if len(output_links) == 1 else "per_file"
    job.output_links_json = json.dumps(output_links)
    job.status = "ready" if job.status != "completed" else "completed"
    job.unrestricted_at = now()
    job.updated_at = now()
    job.error_message = None
    job.provider_error_fingerprint = None

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

    if output_links and not had_links:
        emit_notification_event(
            service.notification_service,
            job,
            event_type="job.links_ready",
            severity="info",
            title="Links ready",
            message="Direct links are available for this job.",
        )

    return job
