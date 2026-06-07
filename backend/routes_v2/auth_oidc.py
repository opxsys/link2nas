from flask import Blueprint, current_app, jsonify, make_response, redirect, request

from backend.services_v2.oidc_service import (
    OidcConfigError,
    OidcDisabledError,
    OidcError,
    OidcExchangeError,
    OidcService,
    OidcUserError,
)
from backend.services_v2.rate_limit_service import rate_limit_response


auth_oidc_v2_bp = Blueprint("auth_oidc_v2", __name__, url_prefix="/api/v2/auth/oidc")

_COOKIE = "l2n_oidc_exchange"
_COMPLETE_PATH = "/api/v2/auth/oidc/complete"
_NEXT_CALLBACK = "/next/oidc/callback"
_LOGIN_ERROR = "/next/login?error=oidc_failed"


def _svc() -> OidcService | None:
    return current_app.config.get("OIDC_SERVICE_V2")


# ── GET /initiate ─────────────────────────────────────────────────────────────

@auth_oidc_v2_bp.get("/initiate")
def oidc_initiate():
    limited = rate_limit_response(
        "oidc_initiate", "public",
        limit_attr="V2_RATE_LIMIT_OIDC_INITIATE_MAX",
        window_attr="V2_RATE_LIMIT_OIDC_INITIATE_WINDOW_SECONDS",
    )
    if limited:
        return limited

    svc = _svc()
    if svc is None:
        return jsonify({"error": "OIDC not available"}), 404

    try:
        auth_url, _state = svc.initiate()
    except OidcDisabledError:
        return jsonify({"error": "OIDC is not enabled"}), 404
    except OidcConfigError:
        return jsonify({"error": "OIDC provider unreachable"}), 503
    except OidcError:
        return jsonify({"error": "OIDC unavailable"}), 503

    return redirect(auth_url, 302)


# ── GET /callback ─────────────────────────────────────────────────────────────

@auth_oidc_v2_bp.get("/callback")
def oidc_callback():
    limited = rate_limit_response(
        "oidc_callback", "public",
        limit_attr="V2_RATE_LIMIT_OIDC_CALLBACK_MAX",
        window_attr="V2_RATE_LIMIT_OIDC_CALLBACK_WINDOW_SECONDS",
    )
    if limited:
        return redirect(_LOGIN_ERROR, 302)

    # Provider-side error (e.g. user cancelled, access denied)
    if request.args.get("error"):
        return redirect(_LOGIN_ERROR, 302)

    state = request.args.get("state", "")
    code = request.args.get("code", "")

    if not state or not code:
        return redirect(_LOGIN_ERROR, 302)

    svc = _svc()
    if svc is None:
        return redirect(_LOGIN_ERROR, 302)

    try:
        exchange_code = svc.handle_callback(state, code)
    except OidcError:
        return redirect(_LOGIN_ERROR, 302)

    settings = current_app.config["SETTINGS"]
    ttl = int(getattr(settings, "OIDC_EXCHANGE_CODE_TTL_SECONDS", 60))
    secure = not getattr(settings, "DEBUG", False)

    resp = redirect(_NEXT_CALLBACK, 302)
    resp.set_cookie(
        _COOKIE,
        exchange_code,
        httponly=True,
        secure=secure,
        samesite="Lax",
        max_age=ttl,
        path=_COMPLETE_PATH,
    )
    return resp


# ── POST /complete ────────────────────────────────────────────────────────────

@auth_oidc_v2_bp.post("/complete")
def oidc_complete():
    limited = rate_limit_response(
        "oidc_complete", "public",
        limit_attr="V2_RATE_LIMIT_OIDC_COMPLETE_MAX",
        window_attr="V2_RATE_LIMIT_OIDC_COMPLETE_WINDOW_SECONDS",
    )
    if limited:
        return limited

    exchange_code = request.cookies.get(_COOKIE, "")
    if not exchange_code:
        return jsonify({"error": "No exchange session found"}), 400

    svc = _svc()
    if svc is None:
        return jsonify({"error": "OIDC not available"}), 404

    def _clear(resp):
        resp.delete_cookie(_COOKIE, path=_COMPLETE_PATH)
        return resp

    try:
        raw_token, user = svc.complete_login(exchange_code)
    except OidcExchangeError:
        return _clear(make_response(jsonify({"error": "Invalid or expired session"}), 400))
    except OidcUserError:
        return _clear(make_response(jsonify({"error": "Authentication failed"}), 401))
    except OidcDisabledError:
        return _clear(make_response(jsonify({"error": "OIDC not enabled"}), 404))
    except OidcError:
        return _clear(make_response(jsonify({"error": "Authentication failed"}), 500))

    app_settings = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    session_inactivity_minutes = 30
    if app_settings:
        try:
            session_inactivity_minutes = app_settings.get_session_inactivity_minutes()
        except Exception:
            pass

    resp = make_response(jsonify({
        "token": raw_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
            "is_active": user.is_active,
            "account_expires_at": user.account_expires_at,
            "last_login_at": user.last_login_at,
            "force_password_change": user.force_password_change,
            "session_inactivity_minutes": session_inactivity_minutes,
        },
    }), 200)
    return _clear(resp)
