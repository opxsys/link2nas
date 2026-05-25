from flask import current_app, jsonify

from backend.services_v2.provider_factory import (
    ProviderConfigDisabledError,
    ProviderConfigNotFoundError,
    UnknownProviderError,
)

from backend.routes_v2.settings_support.responses import _error


def test_provider(ctx, data):
    factory = current_app.config["USER_PROVIDER_FACTORY_V2"]
    provider_config_service = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]

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
