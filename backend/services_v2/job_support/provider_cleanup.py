import json

from backend.models.job import Job
from backend.services_v2.user_context import UserContext


def is_unknown_resource_error(exc: Exception) -> bool:
    message = str(exc).lower()

    return (
        ("http 404" in message and "unknown_ressource" in message)
        or "magnet_invalid_id" in message
        or "invalid or expired" in message
        or "not found" in message
        or "unknown resource" in message
    )


def delete_provider_resources_best_effort(
    provider_factory,
    context: UserContext,
    job: Job,
) -> None:
    if not job.provider_resource_id and not job.output_links_json:
        return

    if provider_factory is None:
        return

    provider = provider_factory.get_provider_for_user(
        user_id=context.user_id,
        provider_config_id=job.provider_config_id,
        provider_name=job.provider_name,
    )

    if job.provider_resource_id:
        try:
            provider.delete_torrent(job.provider_resource_id)
        except Exception as exc:
            if not is_unknown_resource_error(exc):
                raise

    try:
        output_links = json.loads(job.output_links_json or "[]")
    except Exception:
        output_links = []

    if not isinstance(output_links, list):
        output_links = []

    for item in output_links:
        if not isinstance(item, dict):
            continue

        download_id = str(
            item.get("provider_download_id")
            or item.get("download_id")
            or ""
        ).strip()

        if not download_id:
            continue

        try:
            provider.delete_download(download_id)
        except Exception as exc:
            if not is_unknown_resource_error(exc):
                raise
