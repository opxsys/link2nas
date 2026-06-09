import logging

from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2._context import get_user_context
from backend.clients.prowlarr_client import ProwlarrClient, ProwlarrClientError
from backend.services_v2.job_support.source_helpers import detect_source_type
from backend.routes_v2.jobs_support.request_validation import _resolve_destination_ref_for_request
from backend.routes_v2.jobs_support.errors import _handle_provider_exception, _handle_destination_exception
from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)

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


# ── POST /jobs ─────────────────────────────────────────────────────────────────

@prowlarr_search_bp.post("/jobs")
def create_job_from_prowlarr_result():
    ctx = get_user_context()

    cache = _cache()
    if cache is None:
        return _error("Search is temporarily unavailable", 503, "PROWLARR_CACHE_UNAVAILABLE")

    data = request.get_json(silent=True) or {}
    result_id = str(data.get("result_id") or "").strip()
    if not result_id:
        return _error("result_id is required")

    cached = cache.get_for_user(result_id, ctx.user_id)
    if cached is None:
        return _error("Result not found or has expired. Please search again.", 404, "PROWLARR_RESULT_NOT_FOUND")

    # Prefer magnet (no provider token) over direct download URL.
    source_value = cached.magnet_url or cached.download_url
    if not source_value:
        return _error("This result has no downloadable URL.", 400, "PROWLARR_NO_URL")

    try:
        source_type = detect_source_type(source_value)
    except ValueError as exc:
        return _error(str(exc), 400, "PROWLARR_INVALID_URL")

    provider_name = data.get("provider_name") or None
    provider_config_id = data.get("provider_config_id") or None
    destination_name = data.get("destination_name") or None
    destination_config_id = data.get("destination_config_id") or None

    svc = current_app.config["JOB_SERVICE_V2"]

    try:
        # Try to resolve the user's default destination.
        # If none is configured, fall back to links-only (not an error).
        try:
            resolved_dest_name, resolved_dest_config_id = _resolve_destination_ref_for_request(
                ctx, destination_name, destination_config_id, send_to_destination=True
            )
        except DestinationConfigNotFoundError:
            resolved_dest_name, resolved_dest_config_id = None, None

        job = svc.create_job(
            context=ctx,
            source_type=source_type,
            source_value=source_value,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
            destination_name=resolved_dest_name,
            destination_config_id=resolved_dest_config_id,
        )

        logger.info("Prowlarr job created: id=%s source_type=%s user=%s", job.id, source_type, ctx.user_id)
        return jsonify({"id": job.id, "status": job.status, "source_type": job.source_type}), 201

    except Exception as exc:
        if isinstance(exc, (
            DestinationConfigNotFoundError,
            DestinationConfigDisabledError,
            UnknownDestinationError,
        )):
            return _handle_destination_exception(exc)
        return _handle_provider_exception(exc)
