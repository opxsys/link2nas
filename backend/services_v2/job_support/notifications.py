from backend.models.job import Job


def emit_notification_event(
    notification_service,
    job: Job,
    *,
    event_type: str,
    severity: str,
    title: str,
    message: str,
    payload: dict | None = None,
) -> None:
    if not notification_service:
        return

    try:
        notification_service.create_event(
            user_id=job.user_id,
            type=event_type,
            severity=severity,
            title=title,
            message=message,
            job_id=job.id,
            payload={
                "source": "job_service",
                "job_id": job.id,
                "job_status": job.status,
                "provider_config_id": job.provider_config_id,
                "provider_name": job.provider_name,
                "provider_profile_name": job.provider_profile_name,
                "provider_status": job.provider_status,
                "destination_config_id": job.destination_config_id,
                "destination_name": job.destination_name,
                "destination_profile_name": job.destination_profile_name,
                "destination_status": job.destination_status,
                **(payload or {}),
            },
            scope="user",
        )
    except Exception:
        # Notification failures must never break job workflows.
        pass


def emit_provider_failed(notification_service, job: Job, exc: Exception) -> None:
    emit_notification_event(
        notification_service,
        job,
        event_type="provider.failed",
        severity="error",
        title="Provider failed",
        message=str(exc),
        payload={"error": str(exc)},
    )
