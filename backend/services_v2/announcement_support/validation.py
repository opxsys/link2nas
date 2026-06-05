from datetime import datetime, timezone

from backend.services_v2.announcement_support.constants import VALID_TYPES, VALID_SEVERITIES


def validate_announcement_payload(data: dict) -> None:
    if "type" in data and data["type"] not in VALID_TYPES:
        raise ValueError(
            f"Invalid type '{data['type']}'. Must be one of: {', '.join(sorted(VALID_TYPES))}"
        )
    if "severity" in data and data["severity"] not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{data['severity']}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )


def _parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 datetime string, returning a timezone-aware datetime."""
    text = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid date format: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def validate_announcement_dates(data: dict, existing=None) -> None:
    """Validate starts_at / ends_at coherence.

    ``existing`` should be the current Announcement instance for PATCH updates
    so that unchanged fields are resolved from stored values.
    """

    def _date(key):
        """Return the effective string value for a date field, or None if absent/empty."""
        if key in data:
            val = data[key]
        elif existing is not None:
            val = getattr(existing, key, None)
        else:
            val = None
        return val if (val and isinstance(val, str) and val.strip()) else None

    def _active():
        """Return the effective is_active boolean, defaulting to True when absent."""
        if "is_active" in data:
            val = data["is_active"]
            return bool(val) if val is not None else True
        if existing is not None:
            val = getattr(existing, "is_active", None)
            return bool(val) if val is not None else True
        return True

    starts_raw = _date("starts_at")
    ends_raw = _date("ends_at")
    is_active = _active()

    if not starts_raw and not ends_raw:
        return

    starts_dt = _parse_iso(starts_raw) if starts_raw else None
    ends_dt = _parse_iso(ends_raw) if ends_raw else None

    if starts_dt and ends_dt and ends_dt <= starts_dt:
        raise ValueError("End date must be after start date.")

    if ends_dt and is_active and ends_dt <= datetime.now(timezone.utc):
        raise ValueError("End date must be in the future for an active announcement.")
