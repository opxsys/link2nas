import json

from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.source_helpers import filename_from_path


def build_output_links(provider_factory, context: UserContext, job: Job) -> list[dict]:
    payload = json.loads(job.provider_payload_json or "{}")
    links = payload.get("links") or []
    files = payload.get("files") or []

    if not links and job.source_type == "direct_link":
        links = [job.source_value]

    if not links:
        raise ValueError("No provider links available")

    if provider_factory is None:
        raise RuntimeError("Provider factory is not configured")

    provider = provider_factory.get_provider_for_user(
        user_id=context.user_id,
        provider_config_id=job.provider_config_id,
        provider_name=job.provider_name,
    )

    output_links = []

    for index, link in enumerate(links):
        file_meta = files[index] if index < len(files) and isinstance(files[index], dict) else {}

        result = provider.unrestrict_link(link)
        download_url = result.get("download")

        if not download_url:
            raise ValueError("Provider returned no download URL")

        relative_path = file_meta.get("path") or result.get("filename")
        filename = result.get("filename") or filename_from_path(relative_path)

        output_links.append({
            "url": download_url,
            "filename": filename,
            "filesize": result.get("filesize") or file_meta.get("bytes"),
            "provider_download_id": result.get("id"),
            "debrid_link": link,
            "file_id": file_meta.get("id") or index + 1,
            "relative_path": relative_path,
            "path": relative_path,
        })

    return output_links
