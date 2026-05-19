import hashlib
import logging
import uuid
from pathlib import Path
from uuid import uuid4
from datetime import UTC, datetime

from flask import Blueprint, Response, current_app, jsonify, request
from werkzeug.utils import secure_filename

from backend.models.external_client_submission import ExternalClientSubmission
from backend.routes_v2._context import ApiAuthError
from backend.services_v2.user_context import UserContext
from backend.services_v2.rate_limit_service import rate_limit_response

logger = logging.getLogger(__name__)


qbittorrent_compat_v2_bp = Blueprint(
    "qbittorrent_compat_v2",
    __name__,
    url_prefix="/qbittorrent/api/v2",
)


def _safe_input_hash(value: str | bytes | None) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="ignore")

    return hashlib.sha256(raw).hexdigest()[:16]


def _safe_source_summary(value: str | None) -> dict:
    raw = str(value or "").strip()

    if not raw:
        return {
            "input_type": "empty",
            "input_hash": None,
        }

    if raw.startswith("magnet:?"):
        return {
            "input_type": "magnet",
            "input_hash": _safe_input_hash(raw),
        }

    if raw.startswith("http://") or raw.startswith("https://"):
        return {
            "input_type": "url",
            "input_hash": _safe_input_hash(raw),
        }

    return {
        "input_type": "unknown",
        "input_hash": _safe_input_hash(raw),
    }


def _friendly_qbit_error(exc: Exception) -> str:
    return str(exc)


def _audit_repo():
    return current_app.config.get("EXTERNAL_CLIENT_SUBMISSION_REPO_V2")


def _create_external_submission_audit(
    *,
    ctx: UserContext,
    input_type: str,
    input_hash: str | None,
    original_name: str | None,
    category: str | None,
) -> str | None:
    repo = _audit_repo()

    if repo is None:
        return None

    timestamp = datetime.now(UTC).isoformat()
    submission_id = str(uuid.uuid4())

    repo.create(
        ExternalClientSubmission(
            id=submission_id,
            user_id=ctx.user_id,
            client_type="qbittorrent_compat",
            source="prowlarr",
            input_type=input_type,
            input_hash=input_hash,
            original_name=original_name,
            category=category,
            provider_config_id=None,
            destination_config_id=None,
            job_id=None,
            status="received",
            error_message=None,
            created_at=timestamp,
            updated_at=timestamp,
        )
    )

    return submission_id


def _update_external_submission_audit(
    submission_id: str | None,
    *,
    job_id: str | None,
    provider_config_id: str | None,
    destination_config_id: str | None,
    status: str,
    error_message: str | None = None,
) -> None:
    if not submission_id:
        return

    repo = _audit_repo()

    if repo is None:
        return

    repo.update_result(
        submission_id,
        job_id=job_id,
        provider_config_id=provider_config_id,
        destination_config_id=destination_config_id,
        status=status,
        error_message=error_message,
        updated_at=datetime.now(UTC).isoformat(),
    )


def _text(value: str, status: int = 200) -> Response:
    return Response(value, status=status, mimetype="text/plain")


def _is_account_expired(user) -> bool:
    raw = getattr(user, "account_expires_at", None)

    if not raw:
        return False

    try:
        expires_at = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return False

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    return expires_at <= datetime.now(UTC)


def _extract_external_api_key() -> str | None:
    auth = request.headers.get("Authorization", "")

    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    header_key = request.headers.get("X-Api-Key")
    if header_key:
        return header_key.strip()

    cookie_key = request.cookies.get("SID")
    if cookie_key:
        return cookie_key.strip()

    form_password = request.form.get("password")
    if form_password:
        return form_password.strip()

    return None


def _get_external_context(required_scope: str = "qbittorrent:write") -> UserContext:
    raw_key = _extract_external_api_key()

    if not raw_key:
        raise ApiAuthError("Missing qBittorrent compatibility API key")

    api_key_service = current_app.config["USER_API_KEY_SERVICE_V2"]
    api_key = api_key_service.verify_external_key(
        raw_key,
        required_scope=required_scope,
    )

    if api_key is None:
        raise ApiAuthError("Invalid API key or missing scope")

    user_repo = current_app.config["USER_REPO_V2"]
    user = user_repo.get_by_id(api_key.user_id)

    if user is None:
        raise ApiAuthError("Invalid user")

    if not user.is_active:
        raise ApiAuthError("User disabled")

    if _is_account_expired(user):
        raise ApiAuthError("Account expired")

    if getattr(user, "force_password_change", False):
        raise ApiAuthError("Password change required")

    return UserContext(
        user_id=user.id,
        role=user.role,
    )


def _get_default_destination_config_id(ctx: UserContext) -> str | None:
    service = current_app.config.get("DESTINATION_CONFIG_SERVICE_V2")

    if not service:
        return None

    destination = service.get_default_destination_config(ctx)

    if not destination or not destination.is_enabled:
        return None

    return destination.id


def _save_uploaded_torrent(uploaded_file) -> str:
    settings = current_app.config["SETTINGS"]

    temp_dir = Path(settings.TEMP_DIR)
    temp_dir.mkdir(parents=True, exist_ok=True)

    filename = str(uploaded_file.filename or "").strip()
    safe_name = secure_filename(filename) or "upload.torrent"

    saved_path = temp_dir / f"{uuid4().hex}_{safe_name}"
    uploaded_file.save(saved_path)

    return str(saved_path)


def _safe_unlink(path: str | None) -> None:
    if not path:
        return

    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


def _create_and_start_line_jobs(ctx: UserContext, raw_text: str) -> list[dict]:
    service = current_app.config["JOB_SERVICE_V2"]

    destination_config_id = _get_default_destination_config_id(ctx)

    results = service.create_jobs_from_lines(
        context=ctx,
        raw_text=raw_text,
        provider_name=None,
        provider_config_id=None,
        destination_name=None,
        destination_config_id=destination_config_id,
    )

    created = []

    for job, reused in results:
        item = {
            "job_id": job.id,
            "provider_config_id": job.provider_config_id,
            "destination_config_id": job.destination_config_id,
            "reused": reused,
            "status": job.status,
            "error": None,
        }

        try:
            if not reused and job.status == "created":
                job = service.start_job(ctx, job.id)

            if (
                destination_config_id
                and not reused
                and job.status == "ready"
                and job.send_to_destination
            ):
                job = service.send_to_destination(
                    ctx,
                    job.id,
                    destination_config_id=destination_config_id,
                )

            item["provider_config_id"] = job.provider_config_id
            item["destination_config_id"] = job.destination_config_id
            item["status"] = job.status

        except Exception as exc:
            safe_error = _friendly_qbit_error(exc)
            item["error"] = safe_error

            try:
                job.status = "failed"
                job.error_message = safe_error
                job.updated_at = datetime.now(UTC).isoformat()
                service.job_repository.update_status_state(job)
            except Exception:
                pass

        created.append(item)

    return created


def _create_and_start_torrent_file_job(ctx: UserContext, uploaded_file) -> dict:
    service = current_app.config["JOB_SERVICE_V2"]

    destination_config_id = _get_default_destination_config_id(ctx)
    saved_path = None
    job = None

    try:
        saved_path = _save_uploaded_torrent(uploaded_file)

        job, reused = service.create_torrent_file_job(
            context=ctx,
            uploaded_path=saved_path,
            provider_name=None,
            provider_config_id=None,
            destination_name=None,
            destination_config_id=destination_config_id,
        )

        if not reused and job.status == "created":
            job = service.start_job(ctx, job.id)

        return {
            "job_id": job.id,
            "provider_config_id": job.provider_config_id,
            "destination_config_id": job.destination_config_id,
            "reused": reused,
            "status": job.status,
            "error": None,
        }

    except Exception as exc:
        safe_error = _friendly_qbit_error(exc)

        if job is not None:
            try:
                job.status = "failed"
                job.error_message = safe_error
                job.updated_at = datetime.now(UTC).isoformat()
                service.job_repository.update_status_state(job)

                return {
                    "job_id": job.id,
                    "provider_config_id": job.provider_config_id,
                    "destination_config_id": job.destination_config_id,
                    "reused": False,
                    "status": "failed",
                    "error": safe_error,
                }
            except Exception:
                pass

        return {
            "job_id": None,
            "provider_config_id": None,
            "destination_config_id": destination_config_id,
            "reused": False,
            "status": "failed",
            "error": safe_error,
        }

    finally:
        _safe_unlink(saved_path)


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