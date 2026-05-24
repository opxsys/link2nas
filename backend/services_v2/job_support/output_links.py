import json

from backend.models.job import Job


def attach_job_metadata_to_output_links(job: Job, output_links: list[dict]) -> None:
    payload = json.loads(job.provider_payload_json or "{}")
    files = payload.get("files") or []

    job_filename = (
        payload.get("filename")
        or payload.get("name")
        or job.provider_resource_id
        or "job"
    )

    for index, item in enumerate(output_links):
        item["job_id"] = job.id
        item["job_filename"] = job_filename

        if index < len(files) and isinstance(files[index], dict):
            item["relative_path"] = (
                files[index].get("path")
                or files[index].get("filename")
                or item.get("filename")
            )
        else:
            item["relative_path"] = (
                item.get("relative_path")
                or item.get("path")
                or item.get("filename")
            )
