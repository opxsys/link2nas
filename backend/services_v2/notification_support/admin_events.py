from backend.services_v2.notification_support.validation import NotificationValidationError


def list_all_events_admin_impl(
    notification_event_repository,
    event_to_public_dict_func,
    limit: int = 100,
    status: str | None = None,
) -> list[dict]:
    limit = int(limit)

    if limit < 1:
        raise NotificationValidationError("limit must be >= 1")

    if limit > 500:
        raise NotificationValidationError("limit must be <= 500")

    clean_status = str(status or "").strip().lower() or None

    if clean_status and clean_status not in {
        "pending",
        "sent",
        "retrying",
        "failed",
        "ignored",
    }:
        raise NotificationValidationError("Unsupported notification event status")

    if not hasattr(notification_event_repository, "list_all"):
        raise NotificationValidationError(
            "Notification event repository does not support admin listing"
        )

    events = notification_event_repository.list_all(
        limit=limit,
        status=clean_status,
    )

    return [event_to_public_dict_func(event) for event in events]
