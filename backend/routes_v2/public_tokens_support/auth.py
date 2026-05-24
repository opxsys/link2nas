import secrets
import uuid
from datetime import UTC, datetime

from flask import current_app

from backend.models.api_token import ApiToken
from backend.utils.time import utc_now_iso

_now = utc_now_iso


def _is_account_expired(user) -> bool:
    raw = getattr(user, "account_expires_at", None)
    if not raw:
        return False

    try:
        expires_at = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return False

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    return expires_at <= datetime.now(UTC)


def _serialize_auth_user(user):
    app_settings = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    session_inactivity_minutes = 30

    if app_settings:
        session_inactivity_minutes = app_settings.get_session_inactivity_minutes()

    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "account_expires_at": user.account_expires_at,
        "last_login_at": user.last_login_at,
        "force_password_change": user.force_password_change,
        "session_inactivity_minutes": session_inactivity_minutes,
    }


def _create_login_token(user):
    token_repo = current_app.config["API_TOKEN_REPO_V2"]
    timestamp = _now()

    raw_token = "l2n_" + secrets.token_urlsafe(32)

    api_token = ApiToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token=raw_token,
        label="magic login token",
        is_active=True,
        created_at=timestamp,
        updated_at=timestamp,
    )

    token_repo.create(api_token)

    return raw_token
