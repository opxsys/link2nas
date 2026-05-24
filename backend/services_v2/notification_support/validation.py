VALID_CHANNELS = {"email", "gotify", "webhook"}
VALID_SEVERITIES = {"info", "warning", "error", "critical"}
VALID_SCOPES = {"user", "system"}


class NotificationValidationError(Exception):
    pass


def require_text(value, field_name: str) -> str:
    text = str(value or "").strip()

    if not text:
        raise NotificationValidationError(f"{field_name} is required")

    return text


def validate_channel(value) -> str:
    channel = str(value or "").strip().lower()

    if channel not in VALID_CHANNELS:
        raise NotificationValidationError("Unsupported notification channel")

    return channel


def validate_severity(value) -> str:
    severity = str(value or "").strip().lower()

    if severity not in VALID_SEVERITIES:
        raise NotificationValidationError("Unsupported notification severity")

    return severity


def validate_scope(value) -> str:
    scope = str(value or "").strip().lower()

    if scope not in VALID_SCOPES:
        raise NotificationValidationError("Unsupported notification scope")

    return scope


def validate_event_types(value) -> list[str]:
    if value is None:
        return []

    if not isinstance(value, list):
        raise NotificationValidationError("event_types must be a list")

    return [str(item).strip() for item in value if str(item).strip()]


def validate_rate_limit(value) -> int:
    try:
        rate = int(value)
    except Exception as exc:
        raise NotificationValidationError("rate_limit_per_hour must be an integer") from exc

    if rate < 0:
        raise NotificationValidationError("rate_limit_per_hour must be >= 0")

    if rate > 1000:
        raise NotificationValidationError("rate_limit_per_hour must be <= 1000")

    return rate


def severity_rank(severity: str) -> int:
    order = {
        "info": 10,
        "warning": 20,
        "error": 30,
        "critical": 40,
    }

    return order.get(str(severity or "").strip().lower(), 0)
