import uuid
from pathlib import Path

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.source_helpers import detect_source_type, hash_file


def create_job_impl(
    service,
    context: UserContext,
    source_type: str,
    source_value: str,
    provider_name: str | None = None,
    destination_name: str | None = None,
    *,
    provider_config_id: str | None = None,
    destination_config_id: str | None = None,
) -> Job:
    timestamp = now()

    provider_config = service._resolve_provider_config(
        context,
        provider_name=provider_name,
        provider_config_id=provider_config_id,
    )

    destination_config = service._resolve_destination_config(
        context,
        destination_name=destination_name,
        destination_config_id=destination_config_id,
        allow_none=True,
    )

    job = Job(
        id=str(uuid.uuid4()),
        user_id=context.user_id,
        source_type=source_type,
        source_value=source_value,
        status="created",
        provider_config_id=provider_config.id,
        provider_name=provider_config.provider_type,
        provider_profile_name=provider_config.name,
        provider_resource_id=None,
        provider_status=None,
        provider_payload_json=None,
        destination_config_id=destination_config.id if destination_config else None,
        destination_name=destination_config.destination_type if destination_config else None,
        destination_profile_name=destination_config.name if destination_config else None,
        output_mode=None,
        output_links_json=None,
        unrestricted_at=None,
        error_message=None,
        created_at=timestamp,
        updated_at=timestamp,
        started_at=None,
        completed_at=None,
        cancelled_at=None,
        send_to_destination=bool(destination_config),
        sent_to_destination=False,
        sent_to_destination_at=None,
        destination_status="pending" if destination_config else None,
        destination_message=None,
        destination_message_key=None,
        destination_message_params=None,
        destination_last_attempt=None,
        destination_path=None,
    )

    service.job_repository.create(job)

    service._emit_notification_event(
        job,
        event_type="job.created",
        severity="info",
        title="Job created",
        message="Job has been created.",
    )

    return job


def create_jobs_from_lines_impl(
    service,
    context: UserContext,
    raw_text: str,
    provider_name: str | None = None,
    destination_name: str | None = None,
    *,
    provider_config_id: str | None = None,
    destination_config_id: str | None = None,
) -> list[tuple[Job, bool]]:
    provider_config = service._resolve_provider_config(
        context,
        provider_name=provider_name,
        provider_config_id=provider_config_id,
    )

    destination_config = service._resolve_destination_config(
        context,
        destination_name=destination_name,
        destination_config_id=destination_config_id,
        allow_none=True,
    )

    lines = [
        line.strip()
        for line in str(raw_text or "").splitlines()
        if line.strip()
    ]

    unique_lines = list(dict.fromkeys(lines))

    if not unique_lines:
        raise ValueError("source_value is required")

    results = []

    for line in unique_lines:
        source_type = detect_source_type(line)

        existing = service.job_repository.get_existing_by_source(
            context.user_id,
            source_type,
            line,
            provider_config_id=provider_config.id,
            provider_name=provider_config.provider_type,
        )

        if existing:
            results.append((existing, True))
            continue

        job = service.create_job(
            context=context,
            source_type=source_type,
            source_value=line,
            provider_config_id=provider_config.id,
            destination_config_id=destination_config.id if destination_config else None,
        )

        results.append((job, False))

    return results


def create_torrent_file_job_impl(
    service,
    context: UserContext,
    uploaded_path: str,
    provider_name: str | None = None,
    destination_name: str | None = None,
    *,
    provider_config_id: str | None = None,
    destination_config_id: str | None = None,
) -> tuple[Job, bool]:
    provider_config = service._resolve_provider_config(
        context,
        provider_name=provider_name,
        provider_config_id=provider_config_id,
    )

    destination_config = service._resolve_destination_config(
        context,
        destination_name=destination_name,
        destination_config_id=destination_config_id,
        allow_none=True,
    )

    torrent_hash = hash_file(uploaded_path)
    source_value = f"torrent:{torrent_hash}"

    cached_path = Path("data/torrents") / f"{torrent_hash}.torrent"
    cached_path.parent.mkdir(parents=True, exist_ok=True)

    if not cached_path.exists():
        cached_path.write_bytes(Path(uploaded_path).read_bytes())

    existing = service.job_repository.get_existing_by_source(
        context.user_id,
        "torrent_file",
        source_value,
        provider_config_id=provider_config.id,
        provider_name=provider_config.provider_type,
    )

    if existing:
        return existing, True

    return service.create_job(
        context=context,
        source_type="torrent_file",
        source_value=source_value,
        provider_config_id=provider_config.id,
        destination_config_id=destination_config.id if destination_config else None,
    ), False


def clone_job_with_provider_impl(
    service,
    context: UserContext,
    job_id: str,
    provider_name: str | None = None,
    destination_name: str | None = None,
    auto_start: bool = False,
    *,
    provider_config_id: str | None = None,
    destination_config_id: str | None = None,
) -> tuple[Job, bool]:
    source_job = service.get_job(context, job_id)

    if source_job is None:
        raise ValueError("Job not found")

    if not source_job.source_type or not source_job.source_value:
        raise ValueError("Job source is not reusable")

    if source_job.source_type not in {"magnet", "torrent_file", "direct_link"}:
        raise ValueError("Job source_type is not reusable")

    provider_config = service._resolve_provider_config(
        context,
        provider_name=provider_name,
        provider_config_id=provider_config_id,
    )

    if provider_config.id == source_job.provider_config_id:
        raise ValueError("New provider profile must be different from current job provider profile")

    if destination_config_id is None and destination_name is None:
        destination_config_id = source_job.destination_config_id if source_job.send_to_destination else None
        destination_name = None if destination_config_id else (
            source_job.destination_name if source_job.send_to_destination else None
        )

    destination_config = service._resolve_destination_config(
        context,
        destination_name=destination_name,
        destination_config_id=destination_config_id,
        allow_none=True,
    )

    existing = service.job_repository.get_existing_by_source(
        context.user_id,
        source_job.source_type,
        source_job.source_value,
        provider_config_id=provider_config.id,
        provider_name=provider_config.provider_type,
    )

    if existing:
        return existing, True

    cloned = service.create_job(
        context=context,
        source_type=source_job.source_type,
        source_value=source_job.source_value,
        provider_config_id=provider_config.id,
        destination_config_id=destination_config.id if destination_config else None,
    )

    if auto_start:
        cloned = service.start_job(context, cloned.id)

    return cloned, False
