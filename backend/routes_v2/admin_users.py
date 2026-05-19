from datetime import UTC, datetime
from backend.utils.time import utc_now_iso
import re
import uuid

from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash

from backend.models.user import User
from backend.routes_v2._context import get_user_context
from backend.services_v2.rate_limit_service import rate_limit_response
from backend.utils.email_templates import build_invitation_email, build_password_reset_email
from backend.utils.user_language import validate_preferred_language


admin_users_bp = Blueprint("admin_users_v2", __name__, url_prefix="/api/v2/admin/users")


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


now = utc_now_iso


def require_super_admin():
    ctx = get_user_context()

    if ctx.role != "super_admin":
        return None, (jsonify({"error": "Forbidden"}), 403)

    return ctx, None


def require_admin_user_management():
    ctx, err = require_super_admin()
    if err:
        return ctx, err

    settings = current_app.config.get("SETTINGS")
    if bool(getattr(settings, "LINK2NAS_SINGLE_USER_MODE", False)):
        return None, (
            jsonify({"error": "User management is disabled in single-user mode"}),
            403,
        )

    return ctx, None


def _parse_optional_datetime(value):
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


def _validate_email(email: str) -> None:
    if not email:
        raise ValueError("email is required")

    if not EMAIL_RE.match(email):
        raise ValueError("Invalid email format")

def _validate_password(password: str, required: bool = True) -> None:
    if not password:
        if required:
            raise ValueError("password is required")
        return

    policy = _get_password_policy()
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

def _validate_validity_dates(valid_from, expires_at) -> None:
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


def serialize_user(user: User):
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_super_admin": user.role == "super_admin",
        "is_active": user.is_active,
        "valid_from": user.valid_from,
        "account_expires_at": user.account_expires_at,
        "email_verified_at": user.email_verified_at,
        "email_verified": bool(user.email_verified_at),
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "last_login_at": user.last_login_at,
        "preferred_language": user.preferred_language,
        "can_use_local_space": bool(user.can_use_local_space),
    }

def _send_account_email(to_email: str, subject: str, body: str):
    smtp_service = current_app.config["SMTP_SERVICE_V2"]
    smtp_service.send_email(
        to_email=to_email,
        subject=subject,
        body=body,
    )

def _email_template_svc():
    return current_app.config.get("EMAIL_TEMPLATE_SERVICE_V2")

def _app_settings_service():
    return current_app.config.get("APP_SETTINGS_SERVICE_V2")


def _get_password_policy() -> dict:
    service = _app_settings_service()
    if not service:
        return {
            "min_length": 10,
            "require_uppercase": False,
            "require_lowercase": False,
            "require_number": False,
            "require_special": False,
        }

    return service.get_password_policy()


def _get_invitation_ttl_hours() -> int:
    service = _app_settings_service()
    if not service:
        return 48
    return service.get_invitation_ttl_hours()


def _get_password_reset_ttl_hours() -> int:
    service = _app_settings_service()
    if not service:
        return 2
    return service.get_password_reset_ttl_hours()


def _get_user_or_404(user_id):
    repo = current_app.config["USER_REPO_V2"]
    user = repo.get_by_id(user_id)
    if not user:
        return None, None, (jsonify({"error": "User not found"}), 404)
    return user, repo, None


def _resolve_app_name() -> str:
    app_svc = _app_settings_service()
    return app_svc.get_effective_app_name(
        env_fallback=getattr(current_app.config.get("SETTINGS"), "APP_NAME", "")
    ) if app_svc else "Link2NAS"


def _check_smtp_available():
    smtp_svc = current_app.config.get("SMTP_SERVICE_V2")
    if not smtp_svc or not smtp_svc.is_email_sending_available():
        return jsonify({"error": "Email sending is not configured."}), 503
    return None


@admin_users_bp.get("")
def list_users():
    ctx, err = require_admin_user_management()
    if err:
        return err

    repo = current_app.config["USER_REPO_V2"]
    users = repo.list_all()

    return jsonify([serialize_user(u) for u in users])


@admin_users_bp.post("")
def create_user():
    ctx, err = require_admin_user_management()
    if err:
        return err

    data = request.get_json(silent=True) or {}

    try:
        email = str(data.get("email") or "").strip().lower()
        creation_mode = str(data.get("creation_mode") or "password").strip().lower()
        password = str(data.get("password") or "")

        if creation_mode not in ("password", "invitation"):
            raise ValueError("Invalid creation mode")

        _validate_email(email)

        if creation_mode == "password":
            _validate_password(password, required=True)

        valid_from = _parse_optional_datetime(data.get("valid_from"))
        account_expires_at = _parse_optional_datetime(data.get("account_expires_at"))
        _validate_validity_dates(valid_from, account_expires_at)

        preferred_language = validate_preferred_language(data.get("preferred_language"))

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    repo = current_app.config["USER_REPO_V2"]

    if repo.get_by_email(email):
        return jsonify({"error": "A user with this email already exists"}), 409

    timestamp = now()
    role = "super_admin" if data.get("is_super_admin") else "user"

    user = User(
        id=str(uuid.uuid4()),
        email=email,
        display_name=str(data.get("display_name") or "").strip() or None,
        role=role,
        is_active=True,
        created_at=timestamp,
        updated_at=timestamp,
        password_hash=generate_password_hash(password) if creation_mode == "password" else None,
        valid_from=valid_from,
        account_expires_at=account_expires_at,
        email_verified_at=timestamp if data.get("email_verified") else None,
        email_verification_token=str(uuid.uuid4()),
        password_reset_token=None,
        password_reset_sent_at=None,
        last_login_at=None,
        force_password_change=bool(data.get("force_password_change")) if creation_mode == "password" else False,
        preferred_language=preferred_language,
        can_use_local_space=bool(data.get("can_use_local_space", False)),
    )

    repo.create(user)

    response = serialize_user(user)

    if creation_mode == "invitation":
        token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]

        token, raw_token = token_service.create_token(
            user_id=user.id,
            token_type="invitation",
            created_by_user_id=ctx.user_id,
            ttl_hours=_get_invitation_ttl_hours(),
        )

        response["invitation"] = {
            "token_type": token.token_type,
            "expires_at": token.expires_at,
            "invitation_url": token_service.build_invitation_url(raw_token),
        }

    return jsonify(response), 201



@admin_users_bp.patch("/<user_id>")
def update_user(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    user, repo, err = _get_user_or_404(user_id)
    if err:
        return err

    data = request.get_json(silent=True) or {}

    try:
        if "email" in data:
            email = str(data.get("email") or "").strip().lower()
            _validate_email(email)

            existing = repo.get_by_email(email)
            if existing and existing.id != user.id:
                return jsonify({"error": "A user with this email already exists"}), 409

            if email != user.email:
                user.email = email
                user.email_verified_at = None
                user.email_verification_token = str(uuid.uuid4())

        if "display_name" in data:
            user.display_name = str(data.get("display_name") or "").strip() or None

        if "is_super_admin" in data:
            user.role = "super_admin" if data.get("is_super_admin") else "user"

        if "is_active" in data:
            user.is_active = bool(data.get("is_active"))

        if "valid_from" in data:
            user.valid_from = _parse_optional_datetime(data.get("valid_from"))

        if "account_expires_at" in data:
            user.account_expires_at = _parse_optional_datetime(data.get("account_expires_at"))

        _validate_validity_dates(user.valid_from, user.account_expires_at)

        if "password" in data and data.get("password"):
            password = str(data.get("password") or "")
            _validate_password(password, required=False)
            user.password_hash = generate_password_hash(password)
            user.password_reset_token = None
            user.password_reset_sent_at = None

        if data.get("email_verified") is True:
            user.email_verified_at = now()
            user.email_verification_token = None

        if data.get("email_verified") is False:
            user.email_verified_at = None
            user.email_verification_token = str(uuid.uuid4())

        if "preferred_language" in data:
            user.preferred_language = validate_preferred_language(data.get("preferred_language"))

        if "can_use_local_space" in data:
            user.can_use_local_space = bool(data.get("can_use_local_space"))

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    user.updated_at = now()
    repo.update(user)

    return jsonify(serialize_user(user))


@admin_users_bp.post("/<user_id>/disable")
def disable_user(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    user, repo, err = _get_user_or_404(user_id)
    if err:
        return err

    if user.id == ctx.user_id:
        return jsonify({"error": "You cannot disable yourself"}), 400

    user.is_active = False
    user.updated_at = now()
    repo.update(user)

    return jsonify(serialize_user(user))


@admin_users_bp.post("/<user_id>/enable")
def enable_user(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    user, repo, err = _get_user_or_404(user_id)
    if err:
        return err

    user.is_active = True
    user.updated_at = now()
    repo.update(user)

    return jsonify(serialize_user(user))


@admin_users_bp.post("/<user_id>/verify-email")
def verify_user_email(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    user, repo, err = _get_user_or_404(user_id)
    if err:
        return err

    user.email_verified_at = now()
    user.email_verification_token = None
    user.updated_at = now()
    repo.update(user)

    return jsonify(serialize_user(user))


@admin_users_bp.post("/<user_id>/reset-password")
def reset_user_password(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    password = str(data.get("password") or "")

    try:
        _validate_password(password, required=True)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    user, repo, err = _get_user_or_404(user_id)
    if err:
        return err

    user.password_hash = generate_password_hash(password)
    user.force_password_change = True
    user.password_reset_token = None
    user.password_reset_sent_at = None
    user.updated_at = now()
    repo.update(user)

    return jsonify(serialize_user(user))


@admin_users_bp.delete("/<user_id>")
def delete_user(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    if user_id == ctx.user_id:
        return jsonify({"error": "You cannot delete yourself"}), 400

    repo = current_app.config["USER_REPO_V2"]
    repo.delete(user_id)

    return "", 204

@admin_users_bp.post("/<user_id>/invitation")
def create_user_invitation(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    repo = current_app.config["USER_REPO_V2"]
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]

    user = repo.get_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    token, raw_token = token_service.create_token(
        user_id=user.id,
        token_type="invitation",
        created_by_user_id=ctx.user_id,
        ttl_hours=_get_invitation_ttl_hours(),
    )

    invitation_url = token_service.build_invitation_url(raw_token)

    return jsonify({
        "token_type": token.token_type,
        "expires_at": token.expires_at,
        "invitation_url": invitation_url,
    }), 201

@admin_users_bp.post("/<user_id>/invitation/email")
def send_user_invitation_email(user_id):
    limited = rate_limit_response(
        "admin_invitation_email",
        user_id,
        limit_attr="V2_RATE_LIMIT_EMAIL_REQUEST_MAX",
        window_attr="V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS",
    )
    if limited:
        return limited

    ctx, err = require_admin_user_management()
    if err:
        return err

    repo = current_app.config["USER_REPO_V2"]
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]

    user = repo.get_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.email:
        return jsonify({"error": "User has no email"}), 400

    err = _check_smtp_available()
    if err:
        return err

    token, raw_token = token_service.create_token(
        user_id=user.id,
        token_type="invitation",
        created_by_user_id=ctx.user_id,
        ttl_hours=_get_invitation_ttl_hours(),
    )

    invitation_url = token_service.build_invitation_url(raw_token)

    app_name = _resolve_app_name()

    svc = _email_template_svc()
    if svc:
        subject, body = svc.render(
            "invitation", user.preferred_language,
            app_name=app_name, url=invitation_url, expires_at=token.expires_at,
        )
    else:
        subject, body = build_invitation_email(
            user.preferred_language, invitation_url, token.expires_at, app_name=app_name
        )

    try:
        _send_account_email(
            to_email=user.email,
            subject=subject,
            body=body,
        )
    except Exception as exc:
        return jsonify({
            "ok": False,
            "error": f"Invitation email failed: {exc}",
        }), 502

    return jsonify({
        "ok": True,
        "message": f"Invitation email sent to {user.email}",
        "token_type": token.token_type,
        "expires_at": token.expires_at,
        "invitation_url": invitation_url,
    }), 201

@admin_users_bp.post("/<user_id>/password-reset-link")
def create_user_password_reset_link(user_id):
    ctx, err = require_admin_user_management()
    if err:
        return err

    repo = current_app.config["USER_REPO_V2"]
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]

    user = repo.get_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    token, raw_token = token_service.create_token(
        user_id=user.id,
        token_type="password_reset",
        created_by_user_id=ctx.user_id,
        ttl_hours=_get_password_reset_ttl_hours(),

    )

    reset_url = token_service.build_password_reset_url(raw_token)

    return jsonify({
        "token_type": token.token_type,
        "expires_at": token.expires_at,
        "reset_url": reset_url,
    }), 201
@admin_users_bp.post("/<user_id>/password-reset-link/email")
def send_user_password_reset_email(user_id):
    limited = rate_limit_response(
        "admin_password_reset_email",
        user_id,
        limit_attr="V2_RATE_LIMIT_EMAIL_REQUEST_MAX",
        window_attr="V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS",
    )
    if limited:
        return limited

    ctx, err = require_admin_user_management()
    if err:
        return err

    repo = current_app.config["USER_REPO_V2"]
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]

    user = repo.get_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.email:
        return jsonify({"error": "User has no email"}), 400

    err = _check_smtp_available()
    if err:
        return err

    token, raw_token = token_service.create_token(
        user_id=user.id,
        token_type="password_reset",
        created_by_user_id=ctx.user_id,
        ttl_hours=_get_password_reset_ttl_hours(),
    )

    reset_url = token_service.build_password_reset_url(raw_token)

    app_name = _resolve_app_name()

    svc = _email_template_svc()
    if svc:
        subject, body = svc.render(
            "password_reset", user.preferred_language,
            app_name=app_name, url=reset_url, expires_at=token.expires_at,
        )
    else:
        subject, body = build_password_reset_email(
            user.preferred_language, reset_url, token.expires_at, app_name=app_name
        )

    try:
        _send_account_email(
            to_email=user.email,
            subject=subject,
            body=body,
        )
    except Exception as exc:
        return jsonify({
            "ok": False,
            "error": f"Password reset email failed: {exc}",
        }), 502

    return jsonify({
        "ok": True,
        "message": f"Password reset email sent to {user.email}",
        "token_type": token.token_type,
        "expires_at": token.expires_at,
        "reset_url": reset_url,
    }), 201