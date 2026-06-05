from pathlib import Path

from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.direct_link_start import start_direct_link_job


def start_job_impl(
    service,
    context: UserContext,
    job_id: str,
) -> "Job | None":
    job = service.get_job(context, job_id)

    if job is None:
        return None

    service._ensure_action_allowed(job, "start")

    if service.provider_factory is None:
        raise RuntimeError("Provider factory is not configured")

    resolved_provider = service.provider_factory.resolve_provider_for_user(
        user_id=context.user_id,
        provider_config_id=job.provider_config_id,
        provider_name=job.provider_name,
    )
    provider = resolved_provider.provider

    job.provider_config_id = resolved_provider.provider_config_id
    job.provider_name = resolved_provider.provider_type
    job.provider_profile_name = resolved_provider.provider_profile_name

    if job.source_type == "magnet":
        try:
            result = provider.add_magnet(job.source_value)
        except Exception as exc:
            service._emit_provider_failed(job, exc)
            service._mark_job_failed_if_provider_error(job, exc)
            raise

        return service._set_started_provider_job(job, result)

    if job.source_type == "torrent_file":
        torrent_hash = str(job.source_value).replace("torrent:", "", 1)
        torrent_path = Path("data/torrents") / f"{torrent_hash}.torrent"

        if not torrent_path.exists():
            raise ValueError("Torrent file content is no longer available")

        try:
            result = provider.add_torrent_file(str(torrent_path))
        except Exception as exc:
            service._emit_provider_failed(job, exc)
            service._mark_job_failed_if_provider_error(job, exc)
            raise

        return service._set_started_provider_job(job, result)

    if job.source_type == "direct_link":
        return start_direct_link_job(
            service.job_repository,
            service.notification_service,
            provider,
            job,
        )

    raise ValueError("Unsupported source_type")
