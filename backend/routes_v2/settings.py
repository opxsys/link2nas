import json

from flask import Blueprint, current_app, jsonify, request

from backend.services_v2.smtp_service import SmtpServiceError

from backend.routes_v2._context import get_user_context
from backend.routes_v2.providers import _serialize as serialize_provider
from backend.routes_v2.destinations import _serialize as serialize_destination
from backend.services_v2.provider_factory import (
    ProviderConfigDisabledError,
    ProviderConfigNotFoundError,
    UnknownProviderError,
)
from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)
from backend.services_v2.destinations.synology_destination import SynologyDestinationError


settings_v2_bp = Blueprint("settings_v2", __name__, url_prefix="/api/v2/settings")


def _error(message: str, status_code: int = 400):
    return jsonify({"ok": False, "error": message}), status_code


@settings_v2_bp.get("")
def get_settings_v2():
    ctx = get_user_context()

    provider_service = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]
    destination_service = current_app.config["DESTINATION_CONFIG_SERVICE_V2"]

    providers = provider_service.list_provider_configs(ctx)
    destinations = destination_service.list_destination_configs(ctx)

    return jsonify({
        "providers": [serialize_provider(p) for p in providers],
        "destinations": [serialize_destination(d) for d in destinations],
    })


@settings_v2_bp.post("/provider/test")
def test_provider_v2():
    ctx = get_user_context()
    factory = current_app.config["USER_PROVIDER_FACTORY_V2"]
    provider_config_service = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]

    data = request.get_json(silent=True) or {}

    provider_config_id = data.get("provider_config_id") or data.get("id") or None
    provider_name = data.get("provider_name") or None

    try:
        resolved = factory.resolve_provider_for_user(
            user_id=ctx.user_id,
            provider_config_id=provider_config_id,
            provider_name=provider_name,
        )

        provider = resolved.provider
        user = provider.get_user()
        account_expires_at = user.get("expiration")

        if account_expires_at:
            provider_config_service.update_account_expires_at(
                context=ctx,
                provider_config_id=resolved.provider_config_id,
                account_expires_at=account_expires_at,
            )

    except ProviderConfigNotFoundError as exc:
        return _error(str(exc), 404)
    except ProviderConfigDisabledError as exc:
        return _error(str(exc), 400)
    except UnknownProviderError as exc:
        return _error(str(exc), 400)
    except Exception as exc:
        return _error(f"Provider test failed: {exc}", 502)

    return jsonify({
        "ok": True,
        "provider_config_id": resolved.provider_config_id,
        "provider_name": resolved.provider_type,
        "provider_type": resolved.provider_type,
        "provider_profile_name": resolved.provider_profile_name,
        "provider_user": user,
        "account_expires_at": account_expires_at,
    })


@settings_v2_bp.post("/destination/test")
def test_destination_v2():
    ctx = get_user_context()

    data = request.get_json(silent=True) or {}

    destination_config_id = data.get("destination_config_id") or data.get("id") or None
    destination_name = data.get("destination_name") or None

    factory = current_app.config["USER_DESTINATION_FACTORY_V2"]

    try:
        resolved = factory.resolve_destination_for_user(
            user_id=ctx.user_id,
            destination_config_id=destination_config_id,
            destination_name=destination_name,
            allow_links_only=False,
        )
    except DestinationConfigNotFoundError as exc:
        return _error(str(exc), 404)
    except DestinationConfigDisabledError as exc:
        return _error(str(exc), 400)
    except UnknownDestinationError as exc:
        return _error(str(exc), 400)

    if resolved.config is None:
        return jsonify({
            "ok": True,
            "destination_name": "links_only",
            "destination_type": None,
            "destination_profile_name": None,
            "message": "links-only mode does not require connectivity test",
        })

    if resolved.name == "local":
        result = resolved.destination.test_connection()
        status_code = 200 if result.get("ok") else 502

        result.setdefault("destination_config_id", resolved.destination_config_id)
        result.setdefault("destination_name", resolved.destination_type)
        result.setdefault("destination_type", resolved.destination_type)
        result.setdefault("destination_profile_name", resolved.destination_profile_name)

        return jsonify(result), status_code

    if resolved.name == "synology":
        try:
            result = resolved.destination.test_connection()
        except SynologyDestinationError as exc:
            return _error(str(exc), 502)
        except Exception as exc:
            return _error(f"NAS test failed: {exc}", 502)

        result.setdefault("destination_config_id", resolved.destination_config_id)
        result.setdefault("destination_name", resolved.destination_type)
        result.setdefault("destination_type", resolved.destination_type)
        result.setdefault("destination_profile_name", resolved.destination_profile_name)

        return jsonify(result)

    return _error(f"Unsupported destination test: {resolved.name}", 400)


@settings_v2_bp.post("/notification/test")
def test_notification_config_v2():
    ctx = get_user_context()

    data = request.get_json(silent=True) or {}
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
