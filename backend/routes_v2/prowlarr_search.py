import json
import logging
from pathlib import Path
from uuid import uuid4

import requests

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from backend.routes_v2._context import get_user_context
from backend.utils.time import utc_now_iso as _utc_now
from backend.clients.prowlarr_client import ProwlarrClient, ProwlarrClientError
from backend.routes_v2.jobs_support.request_validation import _resolve_destination_ref_for_request
from backend.routes_v2.jobs_support.errors import (
    _handle_provider_exception,
    _handle_destination_exception,
    safe_provider_error_message,
    is_provider_client_error,
)
from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)

logger = logging.getLogger(__name__)

prowlarr_search_bp = Blueprint(
    "prowlarr_search_v2", __name__, url_prefix="/api/v2/prowlarr"
)

_TORRENT_CONNECT_TIMEOUT = 10
_TORRENT_READ_TIMEOUT = 30
_TORRENT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB


# ── Helpers ────────────────────────────────────────────────────────────────────

class _ProwlarrFetchError(Exception):
    """Raised when the server-side torrent download fails."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _fetch_prowlarr_torrent(download_url: str) -> bytes:
    """Download a .torrent from Prowlarr server-side. URL is never logged."""
    try:
        resp = requests.get(
            download_url,
            timeout=(_TORRENT_CONNECT_TIMEOUT, _TORRENT_READ_TIMEOUT),
            stream=False,
        )
    except requests.Timeout:
        raise _ProwlarrFetchError("PROWLARR_DOWNLOAD_TIMEOUT", "Torrent download timed out")
    except Exception:
        raise _ProwlarrFetchError("PROWLARR_DOWNLOAD_FAILED", "Failed to connect to indexer")

    if resp.status_code == 404:
        raise _ProwlarrFetchError("PROWLARR_TORRENT_NOT_FOUND", "Torrent not found on indexer (404)")
    if resp.status_code != 200:
        raise _ProwlarrFetchError("PROWLARR_DOWNLOAD_FAILED", f"Indexer returned HTTP {resp.status_code}")

    content = resp.content
    if len(content) > _TORRENT_MAX_BYTES:
        raise _ProwlarrFetchError("PROWLARR_DOWNLOAD_FAILED", "Downloaded content exceeds size limit")
    return content


def _is_valid_torrent(data: bytes) -> bool:
    """Bencoded .torrent dicts always start with 'd'."""
    return len(data) >= 4 and data[:1] == b"d"


def _safe_torrent_name(title: str | None) -> str:
    name = str(title or "prowlarr").strip()
    safe = secure_filename(name) or "prowlarr"
    return safe[:80]


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

    # real_magnet_url is the first genuine magnet:? URI found across magnet_url,
    # download_url, and guid (resolved server-side by the cache).
    # real_torrent_url is download_url only when it's an HTTP(S) URL — never a redirect.
    is_real_magnet = bool(cached.real_magnet_url)
    if not is_real_magnet and not cached.real_torrent_url:
        return _error("This result has no downloadable URL.", 400, "PROWLARR_NO_URL")

    provider_name = data.get("provider_name") or None
    provider_config_id = data.get("provider_config_id") or None
    destination_name = data.get("destination_name") or None
    destination_config_id = data.get("destination_config_id") or None

    svc = current_app.config["JOB_SERVICE_V2"]

    try:
        # Resolve user's default destination; fall back to links-only if none configured.
        try:
            resolved_dest_name, resolved_dest_config_id = _resolve_destination_ref_for_request(
                ctx, destination_name, destination_config_id, send_to_destination=True
            )
        except DestinationConfigNotFoundError:
            resolved_dest_name, resolved_dest_config_id = None, None

        if is_real_magnet:
            # Validated magnet:? URI (may come from magnet_url, download_url, or guid).
            job = svc.create_job(
                context=ctx,
                source_type="magnet",
                source_value=cached.real_magnet_url,
                provider_name=provider_name,
                provider_config_id=provider_config_id,
                destination_name=resolved_dest_name,
                destination_config_id=resolved_dest_config_id,
            )
        else:
            # No real magnet found: fetch the .torrent server-side via real_torrent_url
            # so the provider never receives the Prowlarr URL or its embedded credentials.
            try:
                torrent_bytes = _fetch_prowlarr_torrent(cached.real_torrent_url)
            except _ProwlarrFetchError as exc:
                logger.warning("Prowlarr torrent fetch failed: code=%s", exc.code)
                return _error(exc.message, 502, exc.code)

            if not _is_valid_torrent(torrent_bytes):
                return _error(
                    "The downloaded content is not a valid torrent file.",
                    422,
                    "PROWLARR_INVALID_TORRENT",
                )

            settings = current_app.config["SETTINGS"]
            temp_dir = Path(settings.TEMP_DIR)
            temp_dir.mkdir(parents=True, exist_ok=True)
            safe_name = _safe_torrent_name(cached.title) + ".torrent"
            temp_path = temp_dir / f"{uuid4().hex}_{safe_name}"

            try:
                temp_path.write_bytes(torrent_bytes)
                job, _ = svc.create_torrent_file_job(
                    context=ctx,
                    uploaded_path=str(temp_path),
                    provider_name=provider_name,
                    provider_config_id=provider_config_id,
                    destination_name=resolved_dest_name,
                    destination_config_id=resolved_dest_config_id,
                )
            finally:
                temp_path.unlink(missing_ok=True)

        logger.info("Prowlarr job created: id=%s source_type=%s user=%s", job.id, job.source_type, ctx.user_id)

    except Exception as exc:
        if isinstance(exc, (
            DestinationConfigNotFoundError,
            DestinationConfigDisabledError,
            UnknownDestinationError,
        )):
            return _handle_destination_exception(exc)
        return _handle_provider_exception(exc)

    # Auto-start: call the existing start mechanism immediately after creation.
    # If start fails the job is preserved; return partial success so the frontend
    # can display a clear message and still link to the job.
    started = False
    start_error_msg: str | None = None
    try:
        started_job = svc.start_job(ctx, job.id)
        if started_job is not None:
            job = started_job
            started = True
    except Exception as start_exc:
        logger.warning(
            "Prowlarr job auto-start failed: id=%s reason=%s",
            job.id,
            type(start_exc).__name__,
        )
        if is_provider_client_error(start_exc):
            start_error_msg = safe_provider_error_message(start_exc)
        elif isinstance(start_exc, (ValueError, RuntimeError)):
            start_error_msg = str(start_exc)
        else:
            start_error_msg = "Auto-start failed"

    # Ensure cached.title is visible in Jobs list/detail as a display name.
    # The serializer reads provider_payload.get("name") → filename → jobName().
    # We only write it if the provider hasn't already set a better name.
    if cached.title:
        try:
            payload = json.loads(job.provider_payload_json or "{}") or {}
            if not payload.get("filename") and not payload.get("name"):
                payload["name"] = cached.title
                job.provider_payload_json = json.dumps(payload)
                job.updated_at = _utc_now()
                svc.job_repository.update_provider_state(job)
        except Exception:
            pass  # Non-fatal: display falls back to id

    resp: dict = {
        "id": job.id,
        "status": job.status,
        "source_type": job.source_type,
        "started": started,
    }
    if start_error_msg is not None:
        resp["start_error"] = start_error_msg
    return jsonify(resp), 201
