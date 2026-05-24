import re
from datetime import UTC, datetime

from flask import current_app


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_optional_datetime(value):
    if value in (None, ""):
        return None

    raw = str(value).strip()
    if not raw:
        return None

    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid datetime format")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC).isoformat()


def validate_email(email: str) -> None:
    if not email:
        raise ValueError("email is required")

    if not EMAIL_RE.match(email):
        raise ValueError("Invalid email format")


def get_password_policy() -> dict:
    service = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    if not service:
        return {
            "min_length": 10,
            "require_uppercase": False,
            "require_lowercase": False,
            "require_number": False,
            "require_special": False,
        }

    return service.get_password_policy()


def validate_password(password: str, required: bool = True) -> None:
    if not password:
        if required:
            raise ValueError("password is required")
        return

    policy = get_password_policy()
    min_length = int(policy.get("min_length") or 10)

    if len(password) < min_length:
        raise ValueError(f"Password must contain at least {min_length} characters")

    if policy.get("require_uppercase") and not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")

    if policy.get("require_lowercase") and not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")

    if policy.get("require_number") and not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one number")

    if policy.get("require_special") and not any(not c.isalnum() for c in password):
        raise ValueError("Password must contain at least one special character")


def validate_validity_dates(valid_from, expires_at) -> None:
    current = datetime.now(UTC)

    parsed_valid_from = None
    parsed_expires_at = None

    if valid_from:
        parsed_valid_from = datetime.fromisoformat(valid_from)
        if parsed_valid_from.tzinfo is None:
            parsed_valid_from = parsed_valid_from.replace(tzinfo=UTC)

    if expires_at:
        parsed_expires_at = datetime.fromisoformat(expires_at)
        if parsed_expires_at.tzinfo is None:
            parsed_expires_at = parsed_expires_at.replace(tzinfo=UTC)

        if parsed_expires_at < current:
            raise ValueError("Expiration date cannot be in the past")

    if parsed_valid_from and parsed_expires_at and parsed_valid_from > parsed_expires_at:
        raise ValueError("Valid from date cannot be after expiration date")
