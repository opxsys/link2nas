import json

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext


def resend_to_destination_impl(
    service,
    context: UserContext,
    job_id: str,
    destination_name: str | None = None,
    *,
    destination_config_id: str | None = None,
) -> "Job | None":
    job = service.get_job(context, job_id)

    if job is None:
        return None

    if job.status not in {"ready", "partially_ready", "completed"}:
        service._ensure_action_allowed(job, "resend")

    output_links = json.loads(job.output_links_json or "[]")

    if not isinstance(output_links, list):
        raise ValueError("Invalid output links")

    if service._links_expired_or_invalid(output_links):
        output_links = service._rebuild_links(context, job)
        job.output_links_json = json.dumps(output_links)
        job.unrestricted_at = now()
        service.job_repository.update_unrestrict_state(job)

    if not output_links:
        raise ValueError("No output links available")

    return service.send_to_destination(
        context=context,
        job_id=job_id,
        destination_name=destination_name,
        destination_config_id=destination_config_id,
    )
