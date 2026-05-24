from datetime import UTC, datetime

from backend.models.job import Job


def get_restart_cooldown_seconds(app_settings_service, job: Job) -> int:
    fallback = {
        "default_seconds": 10,
        "realdebrid_seconds": 60,
        "alldebrid_seconds": 8,
    }

    if app_settings_service is None:
        cooldowns = fallback
    else:
        cooldowns = app_settings_service.get_restart_cooldowns()

    provider_name = str(job.provider_name or "").strip().lower()

    if provider_name == "realdebrid":
        return int(cooldowns.get("realdebrid_seconds", fallback["realdebrid_seconds"]))

    if provider_name == "alldebrid":
        return int(cooldowns.get("alldebrid_seconds", fallback["alldebrid_seconds"]))

    return int(cooldowns.get("default_seconds", fallback["default_seconds"]))


def ensure_restart_cooldown_elapsed(app_settings_service, job: Job) -> None:
    if not job.cancelled_at:
        return

    try:
        cancelled_at = datetime.fromisoformat(job.cancelled_at)
    except ValueError:
        return

    if cancelled_at.tzinfo is None:
        cancelled_at = cancelled_at.replace(tzinfo=UTC)

    cooldown_seconds = get_restart_cooldown_seconds(app_settings_service, job)

    if cooldown_seconds <= 0:
        return

    elapsed = (datetime.now(UTC) - cancelled_at).total_seconds()

    if elapsed < cooldown_seconds:
        remaining = max(1, int(cooldown_seconds - elapsed))
        raise ValueError(
            f"Restart temporarily blocked after cancel. Retry in {remaining}s."
        )
