import logging

from flask import Blueprint, Response, current_app, jsonify, request

from backend.services_v2.rate_limit_service import rate_limit_response
from backend.routes_v2.qbittorrent_compat_support.security import (
    _safe_input_hash,
    _safe_source_summary,
)
from backend.routes_v2.qbittorrent_compat_support.auth import (
    _extract_external_api_key,
    _get_external_context,
)
from backend.routes_v2.qbittorrent_compat_support.audit import (
    _create_external_submission_audit,
    _update_external_submission_audit,
)
from backend.routes_v2.qbittorrent_compat_support.jobs import (
    _create_and_start_line_jobs,
    _create_and_start_torrent_file_job,
)

logger = logging.getLogger(__name__)


qbittorrent_compat_v2_bp = Blueprint(
    "qbittorrent_compat_v2",
    __name__,
    url_prefix="/qbittorrent/api/v2",
)


def _text(value: str, status: int = 200) -> Response:
    return Response(value, status=status, mimetype="text/plain")


@qbittorrent_compat_v2_bp.post("/auth/login")
def qbittorrent_auth_login():
    raw_key = request.form.get("password") or request.headers.get("X-Api-Key")

    if not raw_key:
        return _text("Fails.", 403)

    api_key_service = current_app.config["USER_API_KEY_SERVICE_V2"]
    api_key = api_key_service.verify_external_key(
        raw_key,
        required_scope="qbittorrent:write",
    )

    if api_key is None:
        return _text("Fails.", 403)

    response = _text("Ok.")
    response.set_cookie(
        "SID",
        raw_key,
        httponly=True,
        samesite="Lax",
    )
    return response


@qbittorrent_compat_v2_bp.get("/app/version")
def qbittorrent_app_version():
    return _text("4.6.0")


@qbittorrent_compat_v2_bp.get("/app/webapiVersion")
def qbittorrent_webapi_version():
    return _text("2.11.0")


@qbittorrent_compat_v2_bp.get("/app/preferences")
def qbittorrent_app_preferences():
    _get_external_context("qbittorrent:write")

    return jsonify({
        "save_path": "/link2nas",
        "temp_path_enabled": False,
        "queueing_enabled": False,
    })


@qbittorrent_compat_v2_bp.get("/torrents/info")
def qbittorrent_torrents_info():
    _get_external_context("qbittorrent:write")

    return jsonify([])


@qbittorrent_compat_v2_bp.get("/torrents/categories")
def qbittorrent_torrents_categories():
    _get_external_context("qbittorrent:write")

    return jsonify({
        "prowlarr": {
            "name": "prowlarr",
            "savePath": "/link2nas/prowlarr",
        }
    })


@qbittorrent_compat_v2_bp.post("/torrents/add")
def qbittorrent_torrents_add():
    raw_api_key = _extract_external_api_key()

    limited = rate_limit_response(
        "qbittorrent_add",
        raw_api_key or "missing-api-key",
        limit_attr="V2_RATE_LIMIT_QBITTORRENT_ADD_MAX",
        window_attr="V2_RATE_LIMIT_QBITTORRENT_ADD_WINDOW_SECONDS",
    )
    if limited:
        retry_after = limited.headers.get("Retry-After")
        response = _text("Too many attempts. Please try again later.", 429)
        if retry_after:
            response.headers["Retry-After"] = retry_after
        return response

    ctx = _get_external_context("qbittorrent:write")

    urls_values = request.form.getlist("urls")
    urls = "\n".join(
        str(value or "").strip()
        for value in urls_values
        if str(value or "").strip()
    ).strip()

    uploaded_files = request.files.getlist("torrents")
    category = str(request.form.get("category") or "").strip()
    stopped = str(request.form.get("stopped") or request.form.get("paused") or "").strip()

    logger.info(
        "qBittorrent compat add request: user_id=%s category=%s stopped=%s urls_count=%s files_count=%s",
        ctx.user_id,
        category or None,
        stopped or None,
        len(urls_values),
        len(uploaded_files),
    )

    if not urls and not uploaded_files:
        return _text("No torrent or magnet provided", 400)

    results = []

    if urls:
        summary = _safe_source_summary(urls)

        logger.info(
            "qBittorrent compat urls received: user_id=%s input_type=%s input_hash=%s category=%s",
            ctx.user_id,
            summary["input_type"],
            summary["input_hash"],
            category or None,
        )

        audit_id = _create_external_submission_audit(
            ctx=ctx,
            input_type=summary["input_type"],
            input_hash=summary["input_hash"],
            original_name=None,
            category=category or None,
        )

        line_results = _create_and_start_line_jobs(ctx, urls)
        first = line_results[0] if line_results else {}
        first_error = first.get("error")

        _update_external_submission_audit(
            audit_id,
            job_id=first.get("job_id"),
            provider_config_id=first.get("provider_config_id"),
            destination_config_id=first.get("destination_config_id"),
            status="failed" if first_error else "accepted",
            error_message=first_error,
        )

        results.extend(line_results)

    for uploaded_file in uploaded_files:
        if uploaded_file and uploaded_file.filename:
            content = uploaded_file.read()
            file_hash = _safe_input_hash(content)
            uploaded_file.stream.seek(0)

            logger.info(
                "qBittorrent compat torrent file received: user_id=%s filename=%s file_hash=%s category=%s",
                ctx.user_id,
                uploaded_file.filename,
                file_hash,
                category or None,
            )

            audit_id = _create_external_submission_audit(
                ctx=ctx,
                input_type="torrent_file",
                input_hash=file_hash,
                original_name=uploaded_file.filename,
                category=category or None,
            )

            result = _create_and_start_torrent_file_job(ctx, uploaded_file)

            _update_external_submission_audit(
                audit_id,
                job_id=result.get("job_id"),
                provider_config_id=result.get("provider_config_id"),
                destination_config_id=result.get("destination_config_id"),
                status="failed" if result.get("error") else "accepted",
                error_message=result.get("error"),
            )

            results.append(result)

    errors = [item for item in results if item.get("error")]

    if results and len(errors) < len(results):
        return _text("Ok.")

    message = errors[0]["error"] if errors else "Unable to create job"

    logger.warning(
        "qBittorrent compat add failed: user_id=%s category=%s errors_count=%s first_error=%s",
        ctx.user_id,
        category or None,
        len(errors),
        message,
    )

    return _text(message, 400)
