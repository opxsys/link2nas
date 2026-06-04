from backend.utils.time import utc_now_iso

from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash

from backend.routes_v2.admin_users_support.validation import validate_password as _validate_password
from backend.routes_v2.public_tokens_support.app_info import _app_settings_service, _get_magic_login_ttl_minutes
from backend.routes_v2.public_tokens_support.auth import _is_account_expired, _serialize_auth_user, _create_login_token
from backend.routes_v2.public_tokens_support.responses import _token_error
from backend.services_v2.rate_limit_service import rate_limit_response
from backend.utils.email_templates import build_magic_login_email, build_password_reset_email


public_tokens_v2_bp = Blueprint("public_tokens_v2", __name__, url_prefix="/api/v2/public")


now = utc_now_iso


@public_tokens_v2_bp.get("/app-info")
def get_app_info():
    smtp_service = current_app.config.get("SMTP_SERVICE_V2")
    app_svc = _app_settings_service()
    settings_cfg = current_app.config.get("SETTINGS")

    app_name = app_svc.get_effective_app_name(
        env_fallback=getattr(settings_cfg, "APP_NAME", "")
    ) if app_svc else "Link2NAS"

    app_tagline = app_svc.get_effective_app_tagline(
        env_fallback=getattr(settings_cfg, "APP_TAGLINE", "")
    ) if app_svc else ""

    return jsonify({
        "app_name": app_name,
        "app_tagline": app_tagline,
        "email_sending_available": smtp_service.is_email_sending_available() if smtp_service else False,
    })


@public_tokens_v2_bp.get("/tokens/<raw_token>/status")
def token_status(raw_token):
    limited = rate_limit_response(
        "token_status",
        "public",
        limit_attr="V2_RATE_LIMIT_TOKEN_STATUS_MAX",
        window_attr="V2_RATE_LIMIT_TOKEN_STATUS_WINDOW_SECONDS",
    )
    if limited:
        return limited

    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]

    try:
        token = token_service.get_valid_token(raw_token)
    except Exception as exc:
        return _token_error(str(exc), 400)

    return jsonify({
        "valid": True,
        "token_type": token.token_type,
        "expires_at": token.expires_at,
    })


@public_tokens_v2_bp.post("/invitations/accept")
def accept_invitation():
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    user_repo = current_app.config["USER_REPO_V2"]

    data = request.get_json(silent=True) or {}

    raw_token = str(data.get("token") or "")
    password = str(data.get("password") or "")

    limited = rate_limit_response(
        "invitation_accept",
        "public",
        limit_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        window_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    )
    if limited:
        return limited

    try:
        _validate_password(password, required=True)
        token = token_service.get_valid_token(raw_token, expected_type="invitation")
    except Exception as exc:
        return _token_error(str(exc), 400)

    user = user_repo.get_by_id(token.user_id)
    if not user:
        return _token_error("User not found", 404)

    user.password_hash = generate_password_hash(password)
    user.force_password_change = False
    user.email_verified_at = now()
    user.email_verification_token = None
    user.updated_at = now()

    user_repo.update(user)
    token_service.consume_token(token)

    return jsonify({
        "ok": True,
        "message": "Invitation accepted",
    })


@public_tokens_v2_bp.post("/password-reset/confirm")
def confirm_password_reset():
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    user_repo = current_app.config["USER_REPO_V2"]

    data = request.get_json(silent=True) or {}

    raw_token = str(data.get("token") or "")
    password = str(data.get("password") or "")

    limited = rate_limit_response(
        "password_reset_confirm",
        "public",
        limit_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        window_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    )
    if limited:
        return limited

    try:
        _validate_password(password, required=True)
        token = token_service.get_valid_token(raw_token, expected_type="password_reset")
    except Exception as exc:
        return _token_error(str(exc), 400)

    user = user_repo.get_by_id(token.user_id)
    if not user:
        return _token_error("User not found", 404)

    user.password_hash = generate_password_hash(password)
    user.force_password_change = False
    user.password_reset_token = None
    user.password_reset_sent_at = None
    user.updated_at = now()

    user_repo.update(user)
    token_service.consume_token(token)

    return jsonify({
        "ok": True,
        "message": "Password reset confirmed",
    })

@public_tokens_v2_bp.post("/email-verification/confirm")
def confirm_email_verification():
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    user_repo = current_app.config["USER_REPO_V2"]

    data = request.get_json(silent=True) or {}
    raw_token = str(data.get("token") or "")

    limited = rate_limit_response(
        "email_verification_confirm",
        "public",
        limit_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        window_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    )
    if limited:
        return limited

    try:
        token = token_service.get_valid_token(raw_token, expected_type="email_verification")
    except Exception as exc:
        return _token_error(str(exc), 400)

    user = user_repo.get_by_id(token.user_id)
    if not user:
        return _token_error("User not found", 404)

    user.email_verified_at = now()
    user.email_verification_token = None
    user.updated_at = now()

    user_repo.update(user)
    token_service.consume_token(token)

    return jsonify({
        "ok": True,
        "message": "Email verified",
    })

def _get_password_reset_ttl_hours() -> int:
    service = _app_settings_service()
    if not service:
        return 2
    return service.get_password_reset_ttl_hours()


@public_tokens_v2_bp.post("/password-reset/request")
def request_password_reset():
    user_repo = current_app.config["USER_REPO_V2"]
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    smtp_service = current_app.config.get("SMTP_SERVICE_V2")

    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()

    limited = rate_limit_response(
        "password_reset_request",
        email or "missing-email",
        limit_attr="V2_RATE_LIMIT_EMAIL_REQUEST_MAX",
        window_attr="V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS",
    )
    if limited:
        return limited

    if not smtp_service or not smtp_service.is_email_sending_available():
        return jsonify({"error": "Email sending is not configured."}), 503

    generic_response = {
        "ok": True,
        "message": "Si un compte correspond à cette adresse, un lien de réinitialisation sera envoyé.",
    }

    if not email:
        return jsonify(generic_response)

    user = user_repo.get_by_email(email)

    if not user or not user.is_active or _is_account_expired(user):
        return jsonify(generic_response)

    app_svc = _app_settings_service()
    app_name = app_svc.get_effective_app_name(
        env_fallback=getattr(current_app.config.get("SETTINGS"), "APP_NAME", "")
    ) if app_svc else "Link2NAS"

    try:
        token, raw_token = token_service.create_token(
            user_id=user.id,
            token_type="password_reset",
            created_by_user_id=None,
            ttl_hours=_get_password_reset_ttl_hours(),
        )

        reset_url = token_service.build_password_reset_url(raw_token)

        email_svc = current_app.config.get("EMAIL_TEMPLATE_SERVICE_V2")
        if email_svc:
            subject, body = email_svc.render(
                "password_reset", user.preferred_language,
                app_name=app_name, url=reset_url, expires_at=token.expires_at,
            )
        else:
            subject, body = build_password_reset_email(
                user.preferred_language, reset_url, token.expires_at, app_name=app_name
            )
        smtp_service.send_email(to_email=user.email, subject=subject, body=body)
    except Exception:
        return jsonify(generic_response)

    return jsonify(generic_response)


@public_tokens_v2_bp.post("/magic-login/request")
def request_magic_login():
    user_repo = current_app.config["USER_REPO_V2"]
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    smtp_service = current_app.config.get("SMTP_SERVICE_V2")

    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()

    limited = rate_limit_response(
        "magic_login_request",
        email or "missing-email",
        limit_attr="V2_RATE_LIMIT_MAGIC_LOGIN_MAX",
        window_attr="V2_RATE_LIMIT_MAGIC_LOGIN_WINDOW_SECONDS",
    )
    if limited:
        return limited

    if not smtp_service or not smtp_service.is_email_sending_available():
        return jsonify({"error": "Email sending is not configured."}), 503

    # Réponse volontairement vague pour ne pas permettre l'énumération d'emails.
    generic_response = {
        "ok": True,
        "message": "Si un compte existe et peut recevoir un lien, un email de connexion a été envoyé.",
    }

    if not email:
        return jsonify(generic_response)

    user = user_repo.get_by_email(email)

    if not user:
        return jsonify(generic_response)

    if not user.is_active:
        return jsonify(generic_response)

    if _is_account_expired(user):
        return jsonify(generic_response)

    if not user.email_verified_at:
        return jsonify(generic_response)

    app_svc = _app_settings_service()
    app_name = app_svc.get_effective_app_name(
        env_fallback=getattr(current_app.config.get("SETTINGS"), "APP_NAME", "")
    ) if app_svc else "Link2NAS"

    try:
        token, raw_token = token_service.create_token(
            user_id=user.id,
            token_type="magic_login",
            created_by_user_id=None,
            ttl_minutes=_get_magic_login_ttl_minutes(),
        )

        magic_url = token_service.build_magic_login_url(raw_token)

        email_svc = current_app.config.get("EMAIL_TEMPLATE_SERVICE_V2")
        if email_svc:
            subject, body = email_svc.render(
                "magic_login", user.preferred_language,
                app_name=app_name, url=magic_url, expires_at=token.expires_at,
            )
        else:
            subject, body = build_magic_login_email(
                user.preferred_language, magic_url, token.expires_at, app_name=app_name
            )
        smtp_service.send_email(to_email=user.email, subject=subject, body=body)
    except Exception:
        # On reste vague aussi en cas d'erreur SMTP pour éviter de révéler l'existence du compte.
        return jsonify(generic_response)

    return jsonify(generic_response)


@public_tokens_v2_bp.post("/magic-login/confirm")
def confirm_magic_login():
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    user_repo = current_app.config["USER_REPO_V2"]

    data = request.get_json(silent=True) or {}
    raw_token = str(data.get("token") or "")

    limited = rate_limit_response(
        "magic_login_confirm",
        "public",
        limit_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        window_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    )
    if limited:
        return limited

    try:
        token = token_service.get_valid_token(raw_token, expected_type="magic_login")
    except Exception as exc:
        return _token_error(str(exc), 400)

    user = user_repo.get_by_id(token.user_id)
    if not user:
        return _token_error("User not found", 404)

    if not user.is_active:
        return _token_error("User disabled", 401)

    if _is_account_expired(user):
        return _token_error("Account expired", 401)

    if not user.email_verified_at:
        return _token_error("Email not verified", 401)

    timestamp = now()
    user.last_login_at = timestamp
    user.updated_at = timestamp
    user_repo.update(user)

    token_service.consume_token(token)

    login_token = _create_login_token(user)

    return jsonify({
        "token": login_token,
        "user": _serialize_auth_user(user),
    })
