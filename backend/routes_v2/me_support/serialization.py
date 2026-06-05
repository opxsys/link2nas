from flask import current_app


def serialize_me(user):
    app_settings = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    session_inactivity_minutes = 30

    if app_settings:
        try:
            security_settings = app_settings.get_security_settings()
            session_inactivity_minutes = int(
                security_settings.get("token_ttl", {}).get(
                    "session_inactivity_minutes",
                    30,
                )
            )
        except Exception:
            session_inactivity_minutes = 30

    settings = current_app.config.get("SETTINGS")
    single_user_mode = bool(
        getattr(settings, "LINK2NAS_SINGLE_USER_MODE", False)
    )

    smtp_service = current_app.config.get("SMTP_SERVICE_V2")
    email_sending_available = smtp_service.is_email_sending_available() if smtp_service else False

    announcements_enabled = True
    if app_settings:
        try:
            announcements_enabled = app_settings.is_announcements_enabled()
        except Exception:
            announcements_enabled = True

    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "valid_from": user.valid_from,
        "account_expires_at": user.account_expires_at,
        "email_verified_at": user.email_verified_at,
        "email_verified": bool(user.email_verified_at),
        "last_login_at": user.last_login_at,
        "force_password_change": user.force_password_change,
        "session_inactivity_minutes": session_inactivity_minutes,
        "single_user_mode": single_user_mode,
        "preferred_language": user.preferred_language,
        "email_sending_available": email_sending_available,
        "announcements_enabled": announcements_enabled,
        "receive_application_emails": user.receive_application_emails,
        "can_use_local_space": bool(user.can_use_local_space),
        "ui_theme": user.ui_theme or "auto",
    }


def serialize_integration_settings(settings):
    return {
        "prowlarr_enabled": bool(settings.prowlarr_enabled),
        "prowlarr_url": settings.prowlarr_url or "",
        "prowlarr_open_mode": settings.prowlarr_open_mode or "both",
        "home_page": settings.home_page or "dashboard",
    }
