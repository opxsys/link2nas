from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.notifications import emit_provider_failed


def select_files_impl(
    service,
    context: UserContext,
    job_id: str,
    files: str,
) -> "Job | None":
    job = service.get_job(context, job_id)

    if job is None:
        return None

    service._ensure_action_allowed(job, "select_files")

    if not job.provider_resource_id:
        raise ValueError("Job has no provider_resource_id")

    if not files:
        raise ValueError("files is required")

    if service.provider_factory is None:
        raise RuntimeError("Provider factory is not configured")

    provider = service.provider_factory.get_provider_for_user(
        user_id=context.user_id,
        provider_config_id=job.provider_config_id,
        provider_name=job.provider_name,
    )

    try:
        provider.select_files(job.provider_resource_id, files)
    except Exception as exc:
        emit_provider_failed(service.notification_service, job, exc)
        raise

    job.status = "downloading"
    job.provider_status = "files_selected"
    job.updated_at = now()
    job.error_message = None

    service.job_repository.update_after_select_files(job)
    return job
