import logging

from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.prowlarr_config_service import ProwlarrConfigError
from backend.clients.prowlarr_client import ProwlarrClient, ProwlarrClientError

logger = logging.getLogger(__name__)

admin_prowlarr_bp = Blueprint(
    "admin_prowlarr_v2", __name__, url_prefix="/api/v2/admin/prowlarr"
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

@admin_prowlarr_bp.get("")
def get_global_config():
    ctx, err = require_super_admin()
    if err:
        return err

    svc = _svc()
    cfg = svc.get_global_config()
    if cfg is None:
        return jsonify({"enabled": False, "base_url": "", "has_api_key": False})

    return jsonify(svc.to_safe_dict(cfg))


# ── PATCH / ───────────────────────────────────────────────────────────────────

@admin_prowlarr_bp.patch("")
def update_global_config():
    ctx, err = require_super_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    svc = _svc()

    try:
        cfg = svc.save_global_config(
            enabled=bool(data.get("enabled", False)),
            base_url=data.get("base_url"),
            api_key=data.get("api_key"),
            label=data.get("label"),
        )
    except ProwlarrConfigError as exc:
        return _error(str(exc))

    return jsonify(svc.to_safe_dict(cfg))


# ── POST /test ─────────────────────────────────────────────────────────────────

@admin_prowlarr_bp.post("/test")
def test_global_config():
    ctx, err = require_super_admin()
    if err:
        return err

    svc = _svc()
    cfg = svc.get_global_config()

    if cfg is None or not cfg.enabled or not cfg.base_url or not cfg.encrypted_api_key:
        return _error("Prowlarr is not configured", 400, "PROWLARR_NOT_CONFIGURED")

    api_key = svc.get_decrypted_api_key(cfg)
    client = _client_factory()(cfg.base_url, api_key)

    try:
        result = client.test_connection()
    except ProwlarrClientError as exc:
        logger.warning("Prowlarr admin test failed: %s", exc.message)
        return jsonify({"ok": False, "message": exc.message})

    return jsonify({
        "ok": True,
        "message": "Connection successful",
        "version": result["version"],
        "active_indexers": result["active_indexers"],
    })
