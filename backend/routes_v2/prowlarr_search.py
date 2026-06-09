import logging

from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2._context import get_user_context
from backend.clients.prowlarr_client import ProwlarrClient, ProwlarrClientError

logger = logging.getLogger(__name__)

prowlarr_search_bp = Blueprint(
    "prowlarr_search_v2", __name__, url_prefix="/api/v2/prowlarr"
)


def _svc():
    return current_app.config["PROWLARR_CONFIG_SERVICE_V2"]


def _cache():
    return current_app.config.get("PROWLARR_RESULT_CACHE_V2")


def _client_factory():
    return current_app.config.get("PROWLARR_CLIENT_FACTORY", ProwlarrClient)


def _error(message: str, code: int = 400, error_code: str | None = None):
    body = {"error": message}
    if error_code:
        body["code"] = error_code
    return jsonify(body), code


def _resolve_or_error(svc, user_id: str):
    """Returns (effective, None) or (None, error_response)."""
    effective = svc.resolve_effective_config(user_id)
    if not effective.available:
        return None, _error("Prowlarr is not configured", 400, "PROWLARR_NOT_CONFIGURED")
    return effective, None


def _build_client(svc, effective):
    api_key = svc.get_decrypted_api_key(effective.config)
    return _client_factory()(effective.config.base_url, api_key)


# ── GET /status ────────────────────────────────────────────────────────────────

@prowlarr_search_bp.get("/status")
def get_prowlarr_status():
    ctx = get_user_context()
    svc = _svc()
    effective = svc.resolve_effective_config(ctx.user_id)

    if not effective.available:
        return jsonify({"available": False, "source": "none"})

    client = _build_client(svc, effective)
    try:
        info = client.test_connection()
    except ProwlarrClientError as exc:
        logger.warning("Prowlarr status check failed: %s", exc.message)
        return jsonify({
            "available": False,
            "source": effective.source,
            "error": exc.message,
        })

    return jsonify({
        "available": True,
        "source": effective.source,
        "base_url": effective.config.base_url,
        "version": info["version"],
        "active_indexers": info["active_indexers"],
    })


# ── GET /indexers ──────────────────────────────────────────────────────────────

@prowlarr_search_bp.get("/indexers")
def get_prowlarr_indexers():
    ctx = get_user_context()
    svc = _svc()
    effective, err = _resolve_or_error(svc, ctx.user_id)
    if err:
        return err

    client = _build_client(svc, effective)
    try:
        indexers = client.get_indexers()
    except ProwlarrClientError as exc:
        logger.warning("Prowlarr indexers fetch failed: %s", exc.message)
        return _error(exc.message, 502, exc.code)

    return jsonify(indexers)


# ── POST /search ───────────────────────────────────────────────────────────────

@prowlarr_search_bp.post("/search")
def search_prowlarr():
    ctx = get_user_context()
    svc = _svc()
    effective, err = _resolve_or_error(svc, ctx.user_id)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    query = str(data.get("query", "")).strip()
    if not query:
        return _error("query is required")

    categories = data.get("categories") or []
    indexer_ids = data.get("indexer_ids") or []
    try:
        limit = int(data.get("limit") or 50)
        if limit < 1 or limit > 100:
            limit = 50
    except (ValueError, TypeError):
        limit = 50
    min_seeders = data.get("min_seeders")
    if min_seeders is not None:
        try:
            min_seeders = int(min_seeders)
        except (ValueError, TypeError):
            min_seeders = None

    cache = _cache()
    if cache is None:
        return _error("Search is temporarily unavailable", 503, "PROWLARR_CACHE_UNAVAILABLE")

    client = _build_client(svc, effective)
    try:
        raw_results = client.search(
            query,
            categories=categories or None,
            indexer_ids=indexer_ids or None,
            limit=limit,
            min_seeders=min_seeders,
        )
    except ProwlarrClientError as exc:
        logger.warning("Prowlarr search failed: %s", exc.message)
        return _error(exc.message, 502, exc.code)

    safe_results = cache.store_results(raw_results, ctx.user_id)
    return jsonify({
        "source": effective.source,
        "results": safe_results,
    })
