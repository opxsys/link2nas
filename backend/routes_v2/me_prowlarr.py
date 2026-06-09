import logging

from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2._context import get_user_context
from backend.services_v2.prowlarr_config_service import ProwlarrConfigError
from backend.clients.prowlarr_client import ProwlarrClient, ProwlarrClientError

logger = logging.getLogger(__name__)

me_prowlarr_bp = Blueprint(
    "me_prowlarr_v2", __name__, url_prefix="/api/v2/me/prowlarr"
)


def _svc():
    return current_app.config["PROWLARR_CONFIG_SERVICE_V2"]


def _client_factory():
    return current_app.config.get("PROWLARR_CLIENT_FACTORY", ProwlarrClient)


def _error(message: str, code: int = 400, error_code: str | None = None):
    body = {"error": message}
    if error_code:
        body["code"] = error_code
    return jsonify(body), code


# ── GET / ─────────────────────────────────────────────────────────────────────

@me_prowlarr_bp.get("")
def get_user_prowlarr():
    ctx = get_user_context()
    svc = _svc()

    user_cfg = svc.get_user_config(ctx.user_id)
    effective = svc.resolve_effective_config(ctx.user_id)

    return jsonify({
        "user_config": svc.to_safe_dict(user_cfg),
        "effective_config_source": effective.source,
        "search_available": effective.available,
    })


# ── PATCH / ───────────────────────────────────────────────────────────────────

@me_prowlarr_bp.patch("")
def update_user_prowlarr():
    ctx = get_user_context()
    data = request.get_json(silent=True) or {}
    svc = _svc()

    try:
        cfg = svc.save_user_config(
            user_id=ctx.user_id,
            enabled=bool(data.get("enabled", False)),
            base_url=data.get("base_url"),
            api_key=data.get("api_key"),
        )
    except ProwlarrConfigError as exc:
        return _error(str(exc))

    return jsonify(svc.to_safe_dict(cfg))


# ── POST /test ─────────────────────────────────────────────────────────────────

@me_prowlarr_bp.post("/test")
def test_user_prowlarr():
    ctx = get_user_context()
    svc = _svc()

    effective = svc.resolve_effective_config(ctx.user_id)

    if not effective.available:
        return _error("Prowlarr is not configured", 400, "PROWLARR_NOT_CONFIGURED")

    api_key = svc.get_decrypted_api_key(effective.config)
    client = _client_factory()(effective.config.base_url, api_key)

    try:
        result = client.test_connection()
    except ProwlarrClientError as exc:
        logger.warning("Prowlarr user test failed (user=%s): %s", ctx.user_id, exc.message)
        return jsonify({"ok": False, "source": effective.source, "message": exc.message})

    return jsonify({
        "ok": True,
        "source": effective.source,
        "message": "Connection successful",
        "version": result["version"],
        "active_indexers": result["active_indexers"],
    })
