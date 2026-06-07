import json

from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.oidc_provider_service import (
    OidcProviderInUseError,
    OidcProviderNotFoundError,
    OidcProviderSecretError,
    OidcProviderValidationError,
)


admin_oidc_providers_bp = Blueprint(
    "admin_oidc_providers_v2", __name__, url_prefix="/api/v2/admin/oidc-providers"
)


def _svc():
    return current_app.config.get("OIDC_PROVIDER_SERVICE_V2")


def _oidc_svc():
    return current_app.config.get("OIDC_SERVICE_V2")


def _serialize(svc, provider) -> dict:
    """Admin dict with allowed_domains as list[str], no secret fields."""
    d = svc.to_admin_dict(provider)
    try:
        d["allowed_domains"] = json.loads(d.pop("allowed_domains_json", "[]"))
    except Exception:
        d["allowed_domains"] = []
        d.pop("allowed_domains_json", None)
    return d


# ── GET / ─────────────────────────────────────────────────────────────────────

@admin_oidc_providers_bp.get("/")
def list_providers():
    ctx, err = require_super_admin()
    if err:
        return err
    svc = _svc()
    if svc is None:
        return jsonify([])
    return jsonify([_serialize(svc, p) for p in svc.list_all()])


# ── POST / ────────────────────────────────────────────────────────────────────

@admin_oidc_providers_bp.post("/")
def create_provider():
    ctx, err = require_super_admin()
    if err:
        return err
    svc = _svc()
    if svc is None:
        return jsonify({"error": "OIDC provider service not available"}), 503

    data = request.get_json(silent=True) or {}
    raw_secret = str(data.get("client_secret", "") or "")

    try:
        ad = data.get("allowed_domains", [])
        allowed_domains_json = json.dumps(ad) if isinstance(ad, list) else "[]"

        provider = svc.create_provider(
            name=str(data.get("name", "")).strip(),
            slug=str(data.get("slug", "")).strip(),
            issuer=str(data.get("issuer", "")).strip(),
            client_id=str(data.get("client_id", "")).strip(),
            client_secret=raw_secret or None,
            scopes=str(data.get("scopes", "openid email profile")),
            button_label=str(data.get("button_label", "")).strip() or None,
            enabled=bool(data.get("enabled", True)),
            auto_create_users=bool(data.get("auto_create_users", False)),
            allowed_domains_json=allowed_domains_json,
            state_ttl_seconds=int(data.get("state_ttl_seconds", 600)),
            exchange_code_ttl_seconds=int(data.get("exchange_code_ttl_seconds", 60)),
            sort_order=int(data.get("sort_order", 0)),
        )
    except (OidcProviderValidationError, OidcProviderSecretError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Failed to create provider"}), 409

    return jsonify(_serialize(svc, provider)), 201


# ── GET /<provider_id> ────────────────────────────────────────────────────────

@admin_oidc_providers_bp.get("/<provider_id>")
def get_provider(provider_id: str):
    ctx, err = require_super_admin()
    if err:
        return err
    svc = _svc()
    if svc is None:
        return jsonify({"error": "OIDC provider service not available"}), 503
    try:
        provider = svc.get_provider_or_raise(provider_id)
    except OidcProviderNotFoundError:
        return jsonify({"error": "Provider not found"}), 404
    return jsonify(_serialize(svc, provider))


# ── PATCH /<provider_id> ──────────────────────────────────────────────────────

@admin_oidc_providers_bp.patch("/<provider_id>")
def update_provider(provider_id: str):
    ctx, err = require_super_admin()
    if err:
        return err
    svc = _svc()
    if svc is None:
        return jsonify({"error": "OIDC provider service not available"}), 503

    data = request.get_json(silent=True) or {}
    kwargs = {}

    for field in ("name", "issuer", "client_id", "scopes", "button_label"):
        if field in data:
            kwargs[field] = str(data[field])
    for field in ("enabled", "auto_create_users"):
        if field in data:
            kwargs[field] = bool(data[field])
    for field in ("state_ttl_seconds", "exchange_code_ttl_seconds", "sort_order"):
        if field in data:
            kwargs[field] = int(data[field])
    if "allowed_domains" in data:
        ad = data["allowed_domains"]
        kwargs["allowed_domains_json"] = json.dumps(ad) if isinstance(ad, list) else "[]"

    # Explicit secret update: present key means "replace or clear"
    if "client_secret" in data:
        raw = str(data["client_secret"] or "")
        kwargs["client_secret"] = raw or None

    try:
        provider = svc.update_provider(provider_id, **kwargs)
    except OidcProviderNotFoundError:
        return jsonify({"error": "Provider not found"}), 404
    except OidcProviderValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Failed to update provider"}), 500

    return jsonify(_serialize(svc, provider))


# ── DELETE /<provider_id> ─────────────────────────────────────────────────────

@admin_oidc_providers_bp.delete("/<provider_id>")
def delete_provider(provider_id: str):
    ctx, err = require_super_admin()
    if err:
        return err
    svc = _svc()
    if svc is None:
        return jsonify({"error": "OIDC provider service not available"}), 503
    try:
        svc.delete_provider(provider_id)
    except OidcProviderNotFoundError:
        return jsonify({"error": "Provider not found"}), 404
    except OidcProviderInUseError as exc:
        return jsonify({"error": str(exc)}), 409
    return jsonify({"ok": True})


# ── POST /<provider_id>/test-discovery ────────────────────────────────────────

@admin_oidc_providers_bp.post("/<provider_id>/test-discovery")
def test_discovery(provider_id: str):
    ctx, err = require_super_admin()
    if err:
        return err
    svc = _svc()
    oidc_svc = _oidc_svc()
    if svc is None or oidc_svc is None:
        return jsonify({"ok": False, "error": "Service not available"}), 503
    try:
        provider = svc.get_provider_or_raise(provider_id)
    except OidcProviderNotFoundError:
        return jsonify({"error": "Provider not found"}), 404
    try:
        metadata = oidc_svc.fetch_provider_metadata(provider.issuer)
        ok = bool(
            metadata.get("authorization_endpoint")
            and metadata.get("token_endpoint")
            and metadata.get("jwks_uri")
        )
        if ok:
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "Incomplete provider metadata"})
    except Exception:
        return jsonify({"ok": False, "error": "Discovery endpoint unreachable"})
