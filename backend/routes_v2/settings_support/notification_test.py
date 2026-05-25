from flask import current_app, jsonify

from backend.services_v2.smtp_service import SmtpServiceError

from backend.routes_v2.settings_support.responses import _error


def test_notification_config(ctx, data):
    channel = str(data.get("channel") or "").strip().lower()
    config = data.get("config") or {}

    if channel not in {"email", "gotify", "webhook"}:
        return _error("Unsupported notification channel", 400)

    if not isinstance(config, dict):
        return _error("Invalid notification config", 400)

    if channel == "email":
        user_repo = current_app.config["USER_REPO_V2"]
        user = user_repo.get_by_id(ctx.user_id)

        if not user or not user.email_verified_at:
            return _error("Email must be verified before sending email notifications", 400)

        smtp_service = current_app.config.get("SMTP_SERVICE_V2")
        if not smtp_service or not smtp_service.is_email_sending_available():
            return _error("SMTP n'est pas configuré.", 400)

        to_email = str(config.get("to_email") or "").strip()
        if not to_email:
            to_email = str(getattr(user, "email", None) or "").strip()
        if not to_email:
            return _error("Aucun destinataire disponible.", 400)

        channel_name = str(data.get("name") or "").strip()
        lang = str(getattr(user, "preferred_language", None) or "fr").lower()

        app_svc = current_app.config.get("APP_SETTINGS_SERVICE_V2")
        app_name = app_svc.get_effective_app_name() or "Link2NAS" if app_svc else "Link2NAS"
        public_base_url = app_svc.get_effective_public_base_url() or "" if app_svc else ""

        email_template_svc = current_app.config.get("EMAIL_TEMPLATE_SERVICE_V2")
        if email_template_svc:
            subject, body = email_template_svc.render(
                "notification_test",
                lang,
                app_name=app_name,
                channel_name=channel_name,
                channel=channel,
                to_email=to_email,
                config_id="unsaved",
                public_base_url=public_base_url,
            )
        else:
            subject = f"[{app_name}] Test notification"
            if lang == "en":
                body = (
                    f'This is a test email for notification channel "{channel_name}".'
                    if channel_name
                    else "This is a test email for your notification channel."
                )
            else:
                body = (
                    f'Ceci est un email de test pour le canal de notification « {channel_name} ».'
                    if channel_name
                    else "Ceci est un email de test pour votre canal de notification."
                )

        success_msg = f"Test email sent to {to_email}." if lang == "en" else f"Email de test envoyé à {to_email}."

        try:
            smtp_service.send_email(to_email=to_email, subject=subject, body=body)
        except SmtpServiceError as exc:
            return _error(str(exc), 400)

        return jsonify({"ok": True, "message": success_msg})

    if channel == "gotify":
        if not config.get("server_url") or not config.get("token"):
            return _error("Gotify server_url and token are required", 400)

        return jsonify({
            "ok": True,
            "message": "Gotify config accepted. Real send test will be wired with NotificationService.",
        })

    if channel == "webhook":
        if not config.get("url"):
            return _error("Webhook URL is required", 400)

        return jsonify({
            "ok": True,
            "message": "Webhook config accepted. Real send test will be wired with NotificationService.",
        })

    return _error("Unsupported notification channel", 400)
