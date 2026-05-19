import logging

from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.rate_limit_service import KNOWN_ANTI_ABUSE_KINDS, RateLimitService

logger = logging.getLogger(__name__)

admin_security_v2_bp = Blueprint(
    "admin_security_v2",
    __name__,
    url_prefix="/api/v2/admin/security",
)


def _get_limiter() -> RateLimitService | None:
    return current_app.config.get("RATE_LIMIT_SERVICE_V2")


@admin_security_v2_bp.get("/anti-abuse")
def get_anti_abuse():
    _, err = require_super_admin()
    if err:
        return err

    limiter = _get_limiter()
    if limiter is None:
        return jsonify({"error": "rate_limit_service_unavailable"}), 503

    settings = current_app.config["SETTINGS"]
    redis_url = str(getattr(settings, "REDIS_URL", "") or "").strip()
    backend = limiter.get_backend_name()

    counters = []
    for meta in KNOWN_ANTI_ABUSE_KINDS:
        kind = meta["kind"]
        limit_attr = meta["limit_attr"]
        window_attr = meta["window_attr"]

        limit_val = int(getattr(settings, limit_attr, 0))
        window_val = int(getattr(settings, window_attr, 0))

        try:
            snapshot = limiter.get_counter_snapshot(kind)
            entry = {
                "kind": kind,
                "label": meta["label"],
                "limit": limit_val,
                "window_seconds": window_val,
                "configurable": True,
                "status": snapshot.get("status", "ok"),
                "active_identities": snapshot.get("active_identities"),
                "estimated_hits": snapshot.get("estimated_hits"),
            }
            if "ttl_seconds" in snapshot:
                entry["ttl_seconds"] = snapshot["ttl_seconds"]
        except Exception:
            logger.exception("anti-abuse snapshot failed for kind=%s", kind)
            entry = {
                "kind": kind,
                "label": meta["label"],
                "limit": limit_val,
                "window_seconds": window_val,
                "configurable": True,
                "status": "unavailable",
            }

        counters.append(entry)

    result: dict = {
        "backend": backend,
        "redis_enabled": backend == "redis",
        "redis_url_configured": bool(redis_url),
        "key_prefix": limiter.get_key_prefix(),
        "counters": counters,
    }

    if backend == "memory":
        result["note"] = (
            "Memory backend: counters reflect current process state only "
            "and are not shared across workers."
        )

    return jsonify(result)


@admin_security_v2_bp.post("/anti-abuse/reset")
def reset_anti_abuse_all():
    _, err = require_super_admin()
    if err:
        return err

    limiter = _get_limiter()
    if limiter is None:
        return jsonify({"error": "rate_limit_service_unavailable"}), 503

    try:
        results = limiter.reset_all_known()
    except Exception:
        logger.exception("anti-abuse reset_all failed")
        return jsonify({"ok": False, "error": "reset_failed"}), 500

    return jsonify({"ok": True, "results": results})


@admin_security_v2_bp.post("/anti-abuse/reset/<kind>")
def reset_anti_abuse_kind(kind: str):
    _, err = require_super_admin()
    if err:
        return err

    known_kinds = {m["kind"] for m in KNOWN_ANTI_ABUSE_KINDS}
    if kind not in known_kinds:
        return jsonify({"error": "unknown_kind", "kind": kind}), 404

    limiter = _get_limiter()
    if limiter is None:
        return jsonify({"error": "rate_limit_service_unavailable"}), 503

    try:
        result = limiter.reset_kind(kind)
    except Exception:
        logger.exception("anti-abuse reset_kind failed for kind=%s", kind)
        return jsonify({"ok": False, "error": "reset_failed"}), 500

    return jsonify({"ok": True, "kind": kind, **result})
