import secrets
import uuid
from datetime import UTC, datetime
from backend.utils.time import utc_now_iso

from flask import Blueprint, jsonify, request, current_app
from werkzeug.security import check_password_hash

from backend.models.api_token import ApiToken
from backend.services_v2.rate_limit_service import rate_limit_response


auth_v2_bp = Blueprint("auth_v2", __name__, url_prefix="/api/v2/auth")


now = utc_now_iso


def _error(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code


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


@auth_v2_bp.post("/login")
def login_v2():
    user_repo = current_app.config["USER_REPO_V2"]
    token_repo = current_app.config["API_TOKEN_REPO_V2"]

    data = request.get_json(silent=True) or {}

    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")

    limited = rate_limit_response(
        "login",
        email or "missing-email",
        limit_attr="V2_RATE_LIMIT_LOGIN_MAX",
        window_attr="V2_RATE_LIMIT_LOGIN_WINDOW_SECONDS",
    )
    if limited:
        return limited

    if not email:
        return _error("email is required")

    if not password:
        return _error("password is required")

    user = user_repo.get_by_email(email)

    if not user or not user.password_hash:
        return _error("Invalid credentials", 401)

    if not user.is_active:
        return _error("User disabled", 401)

    if _is_account_expired(user):
        return _error("Account expired", 401)

    if not check_password_hash(user.password_hash, password):
        return _error("Invalid credentials", 401)

    timestamp = now()

    user.last_login_at = timestamp
    user.updated_at = timestamp
    user_repo.update(user)

    raw_token = "l2n_" + secrets.token_urlsafe(32)

    token = ApiToken(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token=raw_token,
        label="login token",
        is_active=True,
        created_at=timestamp,
        updated_at=timestamp,
    )

    token_repo.create(token)

    app_settings = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    session_inactivity_minutes = 30

    if app_settings:
        session_inactivity_minutes = app_settings.get_session_inactivity_minutes()

    return jsonify({
        "token": raw_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
            "is_active": user.is_active,
            "account_expires_at": user.account_expires_at,
            "last_login_at": user.last_login_at,
            "force_password_change": user.force_password_change,
            "session_inactivity_minutes": session_inactivity_minutes,
        },
    }), 200


@auth_v2_bp.post("/logout")
def logout_v2():
    api_key = request.headers.get("X-Api-Key")

    if api_key:
        token_repo = current_app.config["API_TOKEN_REPO_V2"]
        token = token_repo.get_active_by_token(api_key)

        if token is not None:
            token_repo.deactivate(token.user_id, token.id)

    return jsonify({"ok": True}), 200
