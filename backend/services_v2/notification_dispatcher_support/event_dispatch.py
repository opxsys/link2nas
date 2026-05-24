import json
from datetime import UTC, datetime, timedelta


def get_triggered_config_ids(event) -> list[str]:
    value = getattr(event, "triggered_by_config_ids", None)

    if isinstance(value, list):
        raw_ids = value
    else:
        raw = getattr(event, "triggered_by_config_ids_json", None)

        if not raw:
            return []

        try:
            decoded = json.loads(raw)
        except Exception:
            return []

        if not isinstance(decoded, list):
            return []

        raw_ids = decoded

    seen = set()
    result = []

    for item in raw_ids:
        config_id = str(item).strip()
        if not config_id or config_id in seen:
            continue

        seen.add(config_id)
        result.append(config_id)

    return result


def dispatch_event(
    user_id: str,
    event,
    notification_event_repository,
    notification_config_repository,
    send_func,
    now_func,
) -> str:
    triggered_config_ids = get_triggered_config_ids(event)

    if not triggered_config_ids:
        notification_event_repository.mark_sent(event.id, now_func())
        return "skipped"

    for config_id in triggered_config_ids:
        config = notification_config_repository.get_by_id(user_id, config_id)

        if not config:
            raise ValueError(f"Notification config not found: {config_id}")

        if not getattr(config, "is_enabled", False):
            continue

        send_func(config, event)

    notification_event_repository.mark_sent(event.id, now_func())
    return "sent"


def _event_max_attempts(event, default: int) -> int:
    try:
        value = int(getattr(event, "max_attempts", None) or default)
    except Exception:
        value = default

    return max(1, value)


def mark_event_failure(
    event,
    exc: Exception,
    notification_event_repository,
    max_attempts: int,
) -> None:
    attempts = int(getattr(event, "attempts", 0) or 0) + 1
    event_max = _event_max_attempts(event, max_attempts)

    if attempts >= event_max:
        notification_event_repository.mark_failed(
            event.id,
            str(exc),
        )
        return

    next_retry_at = (
        datetime.now(UTC) + timedelta(minutes=min(30, attempts * 5))
    ).isoformat()

    notification_event_repository.mark_retrying(
        event.id,
        str(exc),
        next_retry_at,
    )
