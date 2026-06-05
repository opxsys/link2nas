import requests

from backend.services_v2.notification_support.validation import NotificationValidationError
from backend.utils.time import utc_now_iso as now


def test_config_email(
    config,
    decoded,
    user_id: str,
    smtp_service,
    user_repository,
    email_template_service,
    app_settings_service,
    SmtpServiceError,
) -> dict:
    to_email = str(decoded.get("to_email") or "").strip()
    user = None

    if user_repository:
        user = user_repository.get_by_id(user_id)
        if not to_email:
            to_email = str(getattr(user, "email", None) or "").strip() if user else ""
    elif not to_email:
        raise NotificationValidationError("User repository is not configured")

    if not to_email:
        raise NotificationValidationError("Email target is required")

    if not smtp_service:
        raise NotificationValidationError("SMTP service is not configured")

    lang = str(getattr(user, "preferred_language", None) or "fr").lower() if user else "fr"

    app_name = "Link2NAS"
    if app_settings_service:
        app_name = app_settings_service.get_effective_app_name() or "Link2NAS"

    public_base_url = ""
    if app_settings_service:
        public_base_url = app_settings_service.get_effective_public_base_url() or ""

    if email_template_service:
        subject, body = email_template_service.render(
            "notification_test",
            lang,
            app_name=app_name,
            channel_name=config.name,
            channel=config.channel,
            to_email=to_email,
            config_id=config.id,
            public_base_url=public_base_url,
        )
    else:
        subject = f"[{app_name}] Test notification"
        if lang == "en":
            body = f'This is a test email for notification channel "{config.name}".'
        else:
            body = f'Ceci est un email de test pour le canal de notification « {config.name} ».'

    success_msg = f"Test email sent to {to_email}." if lang == "en" else f"Email de test envoyé à {to_email}."

    try:
        smtp_service.send_email(to_email=to_email, subject=subject, body=body)
    except SmtpServiceError as exc:
        raise NotificationValidationError(str(exc)) from exc

    return {
        "ok": True,
        "channel": "email",
        "config_id": config.id,
        "message": success_msg,
    }


def test_config_gotify(config, decoded) -> dict:
    server_url = str(decoded.get("server_url") or "").strip().rstrip("/")
    token = str(decoded.get("token") or "").strip()

    if not server_url:
        raise NotificationValidationError("Gotify server_url is required")

    if not token:
        raise NotificationValidationError("Gotify token is required")

    response = requests.post(
        f"{server_url}/message",
        params={"token": token},
        json={
            "title": "Link2NAS - Test Gotify",
            "message": (
                "Ceci est un message de test depuis Link2NAS.\n\n"
                f"Canal: {config.name}"
            ),
            "priority": 5,
        },
        timeout=8,
    )

    if response.status_code in (401, 403):
        raise NotificationValidationError(
            "Notification authentication failed. Please check the channel token."
        )

    if response.status_code < 200 or response.status_code >= 300:
        raise NotificationValidationError(
            "Notification endpoint returned an error. Please check the channel configuration."
        )

    return {
        "ok": True,
        "channel": "gotify",
        "config_id": config.id,
        "message": "Message de test Gotify envoyé.",
    }


def test_config_webhook(config, decoded) -> dict:
    url = str(decoded.get("url") or "").strip()
    method = str(decoded.get("method") or "POST").strip().upper()
    headers = decoded.get("headers") or {}

    if not url:
        raise NotificationValidationError("Webhook url is required")

    if method not in {"POST", "PUT"}:
        raise NotificationValidationError("Webhook method must be POST or PUT")

    if not isinstance(headers, dict):
        raise NotificationValidationError("Webhook headers must be an object")

    payload = {
        "app": "link2nas",
        "test": True,
        "channel": "webhook",
        "config_id": config.id,
        "config_name": config.name,
        "type": "notification.test",
        "severity": "info",
        "title": "Link2NAS - Test Webhook",
        "message": "Ceci est un message de test depuis Link2NAS.",
        "created_at": now(),
    }

    response = requests.request(
        method,
        url,
        headers=headers,
        json=payload,
        timeout=8,
    )

    if response.status_code in (401, 403):
        raise NotificationValidationError(
            "Notification authentication failed. Please check the channel token or credentials."
        )

    if response.status_code < 200 or response.status_code >= 300:
        raise NotificationValidationError(
            "Notification endpoint returned an error. Please check the channel configuration."
        )

    return {
        "ok": True,
        "channel": "webhook",
        "config_id": config.id,
        "message": "Message de test Webhook envoyé.",
    }
