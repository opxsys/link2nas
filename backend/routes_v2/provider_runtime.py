from flask import Blueprint, jsonify, current_app

from backend.routes_v2._context import get_user_context
from backend.routes_v2.jobs_support.errors import (
    safe_provider_error_message,
    PROVIDER_ERROR_STATUS,
)
from backend.services_v2.provider_factory import (
    ProviderConfigDisabledError,
    ProviderConfigNotFoundError,
    UnknownProviderError,
)
from backend.services_v2.providers.realdebrid_client import (
    RealDebridApiError,
    RealDebridClientError,
)
from backend.services_v2.providers.alldebrid_client import (
    AllDebridApiError,
    AllDebridClientError,
)


provider_runtime_v2_bp = Blueprint(
    "provider_runtime_v2",
    __name__,
    url_prefix="/api/v2/provider-runtime",
)

_PROVIDER_CLIENT_ERRORS = (
    RealDebridApiError,
    RealDebridClientError,
    AllDebridApiError,
    AllDebridClientError,
)


def _extract_expiration(provider_user: dict) -> str | None:
    sources = [provider_user]

    data = provider_user.get("data")
    if isinstance(data, dict):
        sources.append(data)

        user = data.get("user")
        if isinstance(user, dict):
            sources.append(user)

    for source in sources:
        for key in (
            "expiration",
            "expires_at",
            "premium_until",
            "premiumUntil",
            "premiumUntilTimestamp",
            "premium_until_timestamp",
        ):
            value = source.get(key)
            if value:
                return str(value)

    return None


def _test_provider(
    ctx,
    provider_name: str | None = None,
    *,
    provider_config_id: str | None = None,
):
    factory = current_app.config["USER_PROVIDER_FACTORY_V2"]
    provider_config_service = current_app.config["PROVIDER_CONFIG_SERVICE_V2"]

    resolved = factory.resolve_provider_for_user(
        user_id=ctx.user_id,
        provider_name=provider_name,
        provider_config_id=provider_config_id,
    )

    provider = resolved.provider
    provider_user = provider.get_user()

    expiration = _extract_expiration(provider_user or {})

    if expiration:
        provider_config_service.update_account_expires_at(
            context=ctx,
            provider_config_id=resolved.provider_config_id,
            account_expires_at=expiration,
        )

    return {
        "ok": True,
        "provider_config_id": resolved.provider_config_id,
        "provider_name": resolved.provider_type,
        "provider_type": resolved.provider_type,
        "provider_profile_name": resolved.provider_profile_name,
        "account_expires_at": expiration,
        "provider_user": provider_user,
    }


@provider_runtime_v2_bp.get("/me")
def get_current_provider_runtime_v2():
    ctx = get_user_context()

    try:
        return jsonify(_test_provider(ctx))
    except ProviderConfigNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    except ProviderConfigDisabledError as exc:
        return jsonify({"error": str(exc)}), 400
    except UnknownProviderError as exc:
        return jsonify({"error": str(exc)}), 400
    except _PROVIDER_CLIENT_ERRORS as exc:
        return jsonify({"error": safe_provider_error_message(exc)}), PROVIDER_ERROR_STATUS
    except Exception:
        return jsonify({"error": "Provider test failed"}), 502


@provider_runtime_v2_bp.get("/test/<config_ref>")
def test_provider_by_name_v2(config_ref):
    ctx = get_user_context()

    try:
        # V3 first: treat path parameter as provider_config_id.
        return jsonify(_test_provider(ctx, provider_config_id=config_ref))

    except ProviderConfigNotFoundError:
        # Temporary V2 compatibility: allow /test/realdebrid or /test/alldebrid.
        if config_ref not in {"realdebrid", "alldebrid"}:
            return jsonify({"error": "Provider config not found"}), 404

        try:
            return jsonify(_test_provider(ctx, provider_name=config_ref))
        except ProviderConfigNotFoundError as exc:
            return jsonify({"error": str(exc)}), 404
        except ProviderConfigDisabledError as exc:
            return jsonify({"error": str(exc)}), 400
        except UnknownProviderError as exc:
            return jsonify({"error": str(exc)}), 400
        except _PROVIDER_CLIENT_ERRORS as exc:
            return jsonify({"error": safe_provider_error_message(exc)}), PROVIDER_ERROR_STATUS
        except Exception:
            return jsonify({"error": "Provider test failed"}), 502

    except ProviderConfigDisabledError as exc:
        return jsonify({"error": str(exc)}), 400
    except UnknownProviderError as exc:
        return jsonify({"error": str(exc)}), 400
    except _PROVIDER_CLIENT_ERRORS as exc:
        return jsonify({"error": safe_provider_error_message(exc)}), PROVIDER_ERROR_STATUS
    except Exception:
        return jsonify({"error": "Provider test failed"}), 502
