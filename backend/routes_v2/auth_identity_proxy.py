from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.public_tokens_support.auth import _serialize_auth_user
from backend.services_v2.identity_proxy_validators.base import (
    IdentityProxyConfigError,
    IdentityProxyDisabledError,
    IdentityProxyError,
    IdentityProxyUserError,
    IdentityProxyValidationError,
)
from backend.services_v2.rate_limit_service import rate_limit_response


auth_identity_proxy_v2_bp = Blueprint(
    "auth_identity_proxy_v2",
    __name__,
    url_prefix="/api/v2/auth/identity-proxy",
)


def _svc():
    return current_app.config.get("IDENTITY_PROXY_AUTH_SERVICE_V2")


@auth_identity_proxy_v2_bp.post("/login")
def identity_proxy_login():
    limited = rate_limit_response(
        "identity_proxy_login",
        "public",
        limit_attr="V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX",
        window_attr="V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_WINDOW_SECONDS",
    )
    if limited:
        return limited

    svc = _svc()
    if svc is None:
        return jsonify({"error": "Identity proxy authentication is not available"}), 404

    try:
        raw_token, user = svc.authenticate(request.headers)
    except IdentityProxyDisabledError:
        return jsonify({"error": "Identity proxy authentication is not available"}), 404
    except IdentityProxyValidationError:
        return jsonify({"error": "Authentication failed"}), 401
    except IdentityProxyUserError:
        return jsonify({"error": "Authentication failed"}), 401
    except IdentityProxyConfigError:
        return jsonify({"error": "Identity proxy authentication is not configured"}), 503
    except IdentityProxyError:
        return jsonify({"error": "Authentication failed"}), 500

    return jsonify({
        "token": raw_token,
        "user": _serialize_auth_user(user),
    }), 200
