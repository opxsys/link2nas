import json

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.status_actions import map_provider_status
from backend.services_v2.job_support.task_guard import reload_job


def refresh_job_impl(
    service,
    context: UserContext,
    job_id: str,
) -> "Job | None":
    job = reload_job(service, context, job_id, task_type="provider_refresh", require_active=True)

    if job is None:
        return None

    service._ensure_action_allowed(job, "refresh")

    if not job.provider_resource_id:
        raise ValueError("Job has no provider_resource_id")

    if service.provider_factory is None:
        raise RuntimeError("Provider factory is not configured")

    provider = service.provider_factory.get_provider_for_user(
        user_id=context.user_id,
        provider_config_id=job.provider_config_id,
        provider_name=job.provider_name,
    )

    try:
        info = provider.get_torrent_info(job.provider_resource_id)
    except Exception as exc:
        terminal = service._record_provider_failure(context, job, exc)
        if terminal or service.get_job(context, job_id) is None:
            return service.get_job(context, job_id)
        raise

    job = reload_job(service, context, job_id, task_type="provider_refresh_post_call", require_active=True)
    if job is None:
        return None
    job.provider_error_fingerprint = None

    provider_status = info.get("status")

    if provider_status == "waiting_files_selection":
        files_to_select = service._resolve_files_to_select(info)

        try:
            provider.select_files(job.provider_resource_id, files_to_select)
        except Exception as exc:
            terminal = service._record_provider_failure(context, job, exc)
            if terminal or service.get_job(context, job_id) is None:
                return service.get_job(context, job_id)
            raise

        job = reload_job(service, context, job_id, task_type="provider_file_selection_post_call", require_active=True)
        if job is None:
            return None

        job.status = "downloading"
        job.provider_status = "files_selected"
        job.provider_payload_json = json.dumps(info)
        job.updated_at = now()
        job.error_message = None

        service.job_repository.update_after_select_files(job)
        return job

    job.provider_status = provider_status
    job.provider_payload_json = json.dumps(info)
    job.status = map_provider_status(provider_status)
    job.updated_at = now()
    job.error_message = None

    if job.status == "downloaded":
        job.completed_at = now()
        service.job_repository.update_refresh_state(job)

        job = service.unrestrict_job(context, job.id)

        if job and job.send_to_destination:
            job = service.send_to_destination(context, job.id)

        return job

    service.job_repository.update_refresh_state(job)
    return job
