from datetime import UTC, datetime

from flask import request, current_app
from werkzeug.exceptions import Unauthorized

from backend.services_v2.user_context import UserContext


class ApiAuthError(Unauthorized):
    def __init__(self, message: str):
        super().__init__(description=message)
        self.message = message


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


def get_user_context() -> UserContext:
    settings = current_app.config["SETTINGS"]

    if getattr(settings, "LINK2NAS_SINGLE_USER_MODE", False):
        single_user_service = current_app.config["SINGLE_USER_SERVICE_V2"]
        user = single_user_service.get_or_create_single_user()

        if not user.is_active:
            raise ApiAuthError("User disabled")

        return UserContext(
            user_id=user.id,
            role=user.role,
        )

    api_key = request.headers.get("X-Api-Key")

    if not api_key:
        raise ApiAuthError("Missing X-Api-Key header")

    token_repo = current_app.config["API_TOKEN_REPO_V2"]
    token = token_repo.get_active_by_token(api_key)

    if token is None:
        raise ApiAuthError("Invalid API key")

    user_repo = current_app.config["USER_REPO_V2"]
    user = user_repo.get_by_id(token.user_id)

    if user is None:
        raise ApiAuthError("Invalid user")

    if not user.is_active:
        raise ApiAuthError("User disabled")

    if _is_account_expired(user):
        raise ApiAuthError("Account expired")

    allowed_when_password_change_required = {
        "/api/v2/me",
        "/api/v2/me/password",
    }

    if getattr(user, "force_password_change", False):
        if request.path not in allowed_when_password_change_required:
            raise ApiAuthError("Password change required")

    return UserContext(
        user_id=user.id,
        role=user.role,
    )