from datetime import UTC, datetime

from flask import current_app, request

from backend.routes_v2._context import ApiAuthError
from backend.services_v2.user_context import UserContext


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


def _extract_external_api_key() -> str | None:
    auth = request.headers.get("Authorization", "")

    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    header_key = request.headers.get("X-Api-Key")
    if header_key:
        return header_key.strip()

    cookie_key = request.cookies.get("SID")
    if cookie_key:
        return cookie_key.strip()

    form_password = request.form.get("password")
    if form_password:
        return form_password.strip()

    return None


def _get_external_context(required_scope: str = "qbittorrent:write") -> UserContext:
    raw_key = _extract_external_api_key()

    if not raw_key:
        raise ApiAuthError("Missing qBittorrent compatibility API key")

    api_key_service = current_app.config["USER_API_KEY_SERVICE_V2"]
    api_key = api_key_service.verify_external_key(
        raw_key,
        required_scope=required_scope,
    )

    if api_key is None:
        raise ApiAuthError("Invalid API key or missing scope")

    user_repo = current_app.config["USER_REPO_V2"]
    user = user_repo.get_by_id(api_key.user_id)

    if user is None:
        raise ApiAuthError("Invalid user")

    if not user.is_active:
        raise ApiAuthError("User disabled")

    if _is_account_expired(user):
        raise ApiAuthError("Account expired")

    if getattr(user, "force_password_change", False):
        raise ApiAuthError("Password change required")

    return UserContext(
        user_id=user.id,
        role=user.role,
    )
