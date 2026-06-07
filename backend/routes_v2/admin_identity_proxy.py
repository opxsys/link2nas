import json

from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.identity_proxy_validators.base import IdentityProxyConfigError


admin_identity_proxy_bp = Blueprint(
    "admin_identity_proxy_v2",
    __name__,
    url_prefix="/api/v2/admin/identity-proxy",
)


def _svc():
    return current_app.config.get("IDENTITY_PROXY_CONFIG_SERVICE_V2")


def _to_api(svc, config) -> dict:
    """Serialize config for the admin API: allowed_domains as list, config as dict."""
    d = svc.to_admin_dict(config)
    try:
        d["allowed_domains"] = json.loads(d.pop("allowed_domains_json", "[]"))
    except Exception:
        d["allowed_domains"] = []
        d.pop("allowed_domains_json", None)
    try:
        d["config"] = json.loads(d.pop("config_json", "{}"))
    except Exception:
        d["config"] = {}
        d.pop("config_json", None)
    return d


# ── GET /config ───────────────────────────────────────────────────────────────

@admin_identity_proxy_bp.get("/config")
def get_config():
    _, err = require_super_admin()
    if err:
        return err

    svc = _svc()
    if svc is None:
        return jsonify({"enabled": False}), 200

    config = svc.get_first_config()
    if config is None:
        return jsonify({"enabled": False}), 200

    return jsonify(_to_api(svc, config)), 200


# ── PATCH /config ─────────────────────────────────────────────────────────────

@admin_identity_proxy_bp.patch("/config")
def upsert_config():
    _, err = require_super_admin()
    if err:
        return err

    svc = _svc()
    if svc is None:
        return jsonify({"error": "Service not available"}), 503

    data = request.get_json(silent=True) or {}

    config_obj = data.get("config")
    config_json = json.dumps(config_obj) if isinstance(config_obj, dict) else None

    allowed = data.get("allowed_domains")
    allowed_domains_json = json.dumps(allowed) if isinstance(allowed, list) else None

    existing = svc.get_first_config()

    try:
        if existing is None:
            config = svc.create_config(
                name=str(data.get("name", "") or "").strip() or "Identity Proxy",
                provider_type=str(data.get("provider_type", "") or "").strip(),
                label=str(data.get("label", "") or "").strip() or None,
                enabled=bool(data.get("enabled", False)),
                auto_login=bool(data.get("auto_login", False)),
                auto_create_users=bool(data.get("auto_create_users", False)),
                allowed_domains_json=allowed_domains_json or "[]",
                config_json=config_json or "{}",
            )
        else:
            kwargs: dict = {}
            if "name" in data:
                kwargs["name"] = str(data["name"])
            if "label" in data:
                kwargs["label"] = str(data["label"])
            if "enabled" in data:
                kwargs["enabled"] = bool(data["enabled"])
            if "auto_login" in data:
                kwargs["auto_login"] = bool(data["auto_login"])
            if "auto_create_users" in data:
                kwargs["auto_create_users"] = bool(data["auto_create_users"])
            if allowed_domains_json is not None:
                kwargs["allowed_domains_json"] = allowed_domains_json
            if config_json is not None:
                kwargs["config_json"] = config_json
            config = svc.update_config(existing.id, **kwargs)
    except IdentityProxyConfigError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(_to_api(svc, config)), 200


# ── POST /test ────────────────────────────────────────────────────────────────

@admin_identity_proxy_bp.post("/test")
def test_config():
    _, err = require_super_admin()
    if err:
        return err

    svc = _svc()
    if svc is None:
        return jsonify({"ok": False, "error": "Service not available"}), 200

    config = svc.get_first_config()
    if config is None:
        return jsonify({"ok": False, "error": "No identity proxy configuration found"}), 200

    if not config.enabled:
        return jsonify({"ok": False, "error": "Identity proxy is disabled"}), 200

    try:
        cfg = json.loads(config.config_json)
    except Exception:
        return jsonify({"ok": False, "error": "config_json is not valid JSON"}), 200

    if config.provider_type == "cloudflare_access":
        if not cfg.get("team_domain", "").strip():
            return jsonify({"ok": False, "error": "team_domain is missing"}), 200
        if not cfg.get("audience", "").strip():
            return jsonify({"ok": False, "error": "audience is missing"}), 200

    return jsonify({"ok": True}), 200
