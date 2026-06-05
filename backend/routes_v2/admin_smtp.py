import uuid
from backend.utils.time import utc_now_iso

from flask import Blueprint, current_app, jsonify, request

from backend.models.smtp_settings import SmtpSettings
from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.smtp_service import SmtpServiceError
from backend.services_v2.email_support.email_failure import (
    safe_email_error_message,
    EMAIL_ERROR_STATUS,
)


admin_smtp_bp = Blueprint("admin_smtp_v2", __name__, url_prefix="/api/v2/admin/smtp-settings")


now = utc_now_iso


def _bool(value) -> bool:
    return bool(value)


def _int(value, default: int) -> int:
    if value in (None, ""):
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise ValueError("Invalid integer value") from exc


def serialize_smtp_settings(settings):
    if not settings:
        return {
            "enabled": False,
            "host": "",
            "port": 587,
            "username": "",
            "has_password": False,
            "from_email": "",
            "from_name": "",
            "use_tls": True,
            "use_ssl": False,
        }

    return {
        "enabled": settings.enabled,
        "host": settings.host or "",
        "port": settings.port,
        "username": settings.username or "",
        "has_password": bool(settings.encrypted_password),
        "from_email": settings.from_email or "",
        "from_name": settings.from_name or "",
        "use_tls": settings.use_tls,
        "use_ssl": settings.use_ssl,
        "created_at": settings.created_at,
        "updated_at": settings.updated_at,
    }


@admin_smtp_bp.get("")
def get_smtp_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    repo = current_app.config["SMTP_SETTINGS_REPO_V2"]
    settings = repo.get()

    return jsonify(serialize_smtp_settings(settings))


@admin_smtp_bp.put("")
def save_smtp_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}

    repo = current_app.config["SMTP_SETTINGS_REPO_V2"]
    crypto_service = current_app.config["CRYPTO_SERVICE_V2"]

    existing = repo.get()
    timestamp = now()

    try:
        enabled = _bool(data.get("enabled"))
        host = str(data.get("host") or "").strip() or None
        port = _int(data.get("port"), 587)
        username = str(data.get("username") or "").strip() or None
        from_email = str(data.get("from_email") or "").strip() or None
        from_name = str(data.get("from_name") or "").strip() or None
        use_tls = _bool(data.get("use_tls"))
        use_ssl = _bool(data.get("use_ssl"))

        if use_tls and use_ssl:
            return jsonify({"error": "use_tls and use_ssl cannot both be enabled"}), 400

        if enabled:
            if not host:
                return jsonify({"error": "SMTP host is required when enabled"}), 400
            if not from_email:
                return jsonify({"error": "SMTP from_email is required when enabled"}), 400

        raw_password = data.get("password")

        if raw_password:
            encrypted_password = crypto_service.encrypt(str(raw_password))
        elif existing:
            encrypted_password = existing.encrypted_password
        else:
            encrypted_password = None

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    settings = SmtpSettings(
        id=existing.id if existing else str(uuid.uuid4()),
        enabled=enabled,
        host=host,
        port=port,
        username=username,
        encrypted_password=encrypted_password,
        from_email=from_email,
        from_name=from_name,
        use_tls=use_tls,
        use_ssl=use_ssl,
        created_at=existing.created_at if existing else timestamp,
        updated_at=timestamp,
    )

    repo.upsert(settings)

    return jsonify(serialize_smtp_settings(settings))


@admin_smtp_bp.post("/test")
def test_smtp_settings():
    ctx, err = require_super_admin()
    if err:
        return err

    user_repo = current_app.config["USER_REPO_V2"]
    smtp_service = current_app.config["SMTP_SERVICE_V2"]

    user = user_repo.get_by_id(ctx.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.email:
        return jsonify({"error": "Current user has no email"}), 400

    app_svc = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    settings_cfg = current_app.config.get("SETTINGS")
    app_name = app_svc.get_effective_app_name(
        env_fallback=getattr(settings_cfg, "APP_NAME", "")
    ) if app_svc else "Link2NAS"

    public_base_url = (
        app_svc.get_effective_public_base_url(
            env_fallback=getattr(settings_cfg, "PUBLIC_BASE_URL", "")
        ) if app_svc else getattr(settings_cfg, "PUBLIC_BASE_URL", "")
    )
    lang = getattr(user, "preferred_language", None) or "en"

    email_svc = current_app.config.get("EMAIL_TEMPLATE_SERVICE_V2")
    if email_svc:
        subject, body = email_svc.render(
            "smtp_test", lang,
            app_name=app_name, public_base_url=public_base_url,
        )
    else:
        subject = f"{app_name} — Test SMTP"
        body = (
            f"Ceci est un email de test {app_name}.\n\n"
            "Si vous recevez ce message, la configuration SMTP fonctionne correctement."
        )

    try:
        smtp_service.send_email(
            to_email=user.email,
            subject=subject,
            body=body,
        )
    except SmtpServiceError as exc:
        system_event_service = current_app.config.get("SYSTEM_EVENT_SERVICE_V2")

        if system_event_service:
            system_event_service.create_for_super_admins(
                event_type="system.smtp.failed",
                severity="error",
                title="SMTP test failed",
                message=f"SMTP test failed: {exc}",
                component="smtp",
                fingerprint="smtp.test.failed",
                details={
                    "error": str(exc),
                    "route": "/api/v2/admin/smtp-settings/test",
                    "target_email": user.email,
                },
            )

        return jsonify({"ok": False, "error": safe_email_error_message(exc)}), EMAIL_ERROR_STATUS

    return jsonify({
        "ok": True,
        "message": f"Test email sent to {user.email}",
    })
