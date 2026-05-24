from pathlib import Path
from uuid import uuid4

from flask import Blueprint, jsonify, request, current_app
from werkzeug.utils import secure_filename

from backend.services_v2.job_service import JobService, now
from backend.routes_v2._context import get_user_context

from backend.services_v2.destination_factory import (
    DestinationConfigDisabledError,
    DestinationConfigNotFoundError,
    UnknownDestinationError,
)

from backend.routes_v2.jobs_support.errors import (
    _error,
    _handle_provider_exception,
    _handle_destination_exception,
)

from backend.routes_v2.jobs_support.helpers import (
    _bool_from_form,
    _safe_unlink,
)

from backend.routes_v2.jobs_support.serialization import serialize_job

jobs_v2_bp = Blueprint("jobs_v2", __name__, url_prefix="/api/v2/jobs")

ALLOWED_SOURCE_TYPES = {"magnet", "torrent_file", "direct_link"}
ALLOWED_PROVIDERS = {"realdebrid", "alldebrid"}
ALLOWED_DESTINATIONS = {"synology", "nas", "local", "links_only"}


def _check_local_space_permission(ctx, destination_config_id=None, destination_name=None):
    """Return a 403 error response if destination is local and user lacks permission, else None."""
    is_local = destination_name == "local"
    if not is_local and destination_config_id:
        dest_service = current_app.config.get("DESTINATION_CONFIG_SERVICE_V2")
        if dest_service:
            config = dest_service.get_destination_config(ctx, destination_config_id=destination_config_id)
            if config and config.destination_type == "local":
                is_local = True
    if is_local:
        user_repo = current_app.config["USER_REPO_V2"]
        user = user_repo.get_by_id(ctx.user_id)
        if not user or not user.can_use_local_space:
            return _error("Local space is not allowed for this account.", 403)
    return None


def _resolve_destination_ref_for_request(
    ctx,
    destination_name,
    destination_config_id,
    send_to_destination: bool,
):
    if destination_name == "links_only":
        return None, None

    if destination_config_id:
        return None, destination_config_id

    if destination_name:
        return destination_name, None

    if not send_to_destination:
        return None, None

    destination_factory = current_app.config["USER_DESTINATION_FACTORY_V2"]
    resolved = destination_factory.resolve_destination_for_user(
        user_id=ctx.user_id,
        destination_name=None,
    )

    if resolved.config is None:
        raise DestinationConfigNotFoundError("No default destination config found")

    return None, resolved.destination_config_id


@jobs_v2_bp.post("")
def create_job_v2():
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    data = request.get_json(silent=True) or {}

    source_type = data.get("source_type")
    source_value = data.get("source_value")
    provider_name = data.get("provider_name")
    provider_config_id = data.get("provider_config_id") or data.get("provider_id")
    destination_name = data.get("destination_name")
    destination_config_id = data.get("destination_config_id") or data.get("destination_id")
    send_to_destination = bool(data.get("send_to_destination", False))

    if not source_type:
        return _error("source_type is required")

    if source_type not in ALLOWED_SOURCE_TYPES:
        return _error("invalid source_type")

    if not source_value:
        return _error("source_value is required")

    if provider_name is not None and provider_name not in ALLOWED_PROVIDERS:
        return _error("invalid provider_name")

    if destination_name is not None and destination_name not in ALLOWED_DESTINATIONS:
        return _error("invalid destination_name")

    try:
        destination_name, destination_config_id = _resolve_destination_ref_for_request(
            ctx,
            destination_name,
            destination_config_id,
            send_to_destination,
        )

        err = _check_local_space_permission(ctx, destination_config_id=destination_config_id, destination_name=destination_name)
        if err:
            return err

        job = service.create_job(
            context=ctx,
            source_type=source_type,
            source_value=source_value,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
        )

        return jsonify(serialize_job(job)), 201

    except Exception as exc:
        if isinstance(exc, (
            DestinationConfigNotFoundError,
            DestinationConfigDisabledError,
            UnknownDestinationError,
        )):
            return _handle_destination_exception(exc)

        return _handle_provider_exception(exc)


@jobs_v2_bp.post("/bulk")
def create_jobs_bulk_v2():
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    data = request.get_json(silent=True) or {}

    raw_text = str(data.get("source_value") or "").strip()
    auto_start = bool(data.get("auto_start", False))
    send_to_destination = bool(data.get("send_to_destination", False))
    provider_name = data.get("provider_name")
    provider_config_id = data.get("provider_config_id") or data.get("provider_id")
    destination_name = data.get("destination_name")
    destination_config_id = data.get("destination_config_id") or data.get("destination_id")

    if provider_name is not None and provider_name not in ALLOWED_PROVIDERS:
        return _error("invalid provider_name")

    if destination_name is not None and destination_name not in ALLOWED_DESTINATIONS:
        return _error("invalid destination_name")

    try:
        destination_name, destination_config_id = _resolve_destination_ref_for_request(
            ctx,
            destination_name,
            destination_config_id,
            send_to_destination,
        )

        results = service.create_jobs_from_lines(
            context=ctx,
            raw_text=raw_text,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
        )

        final_results = []

        for job, reused in results:
            item_error = None

            try:
                if auto_start and not reused:
                    job = service.start_job(ctx, job.id)

                if send_to_destination and not reused and job.status == "ready":
                    job = service.send_to_destination(
                        ctx,
                        job.id,
                        destination_name=destination_name,
                        destination_config_id=destination_config_id,
                    )

            except Exception as exc:
                item_error = str(exc)

                job.status = "failed"
                job.error_message = item_error
                job.updated_at = now()
                service.job_repository.update_status_state(job)

            final_results.append({
                "job": serialize_job(job),
                "reused": reused,
                "error": item_error,
            })

        return jsonify({"jobs": final_results}), 201

    except Exception as exc:
        if isinstance(exc, (
            DestinationConfigNotFoundError,
            DestinationConfigDisabledError,
            UnknownDestinationError,
        )):
            return _handle_destination_exception(exc)

        return _handle_provider_exception(exc)


@jobs_v2_bp.post("/torrent-file")
def create_torrent_file_job_v2():
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    uploaded_file = request.files.get("file")
    auto_start = _bool_from_form(request.form.get("auto_start"))
    send_to_destination = _bool_from_form(request.form.get("send_to_destination"))
    provider_name = request.form.get("provider_name") or None
    provider_config_id = request.form.get("provider_config_id") or request.form.get("provider_id") or None
    destination_name = request.form.get("destination_name") or None
    destination_config_id = request.form.get("destination_config_id") or request.form.get("destination_id") or None

    if provider_name is not None and provider_name not in ALLOWED_PROVIDERS:
        return _error("invalid provider_name")

    if destination_name is not None and destination_name not in ALLOWED_DESTINATIONS:
        return _error("invalid destination_name")

    try:
        destination_name, destination_config_id = _resolve_destination_ref_for_request(
            ctx,
            destination_name,
            destination_config_id,
            send_to_destination,
        )
    except Exception as exc:
        return _handle_destination_exception(exc)

    if uploaded_file is None:
        return _error("Fichier .torrent manquant.", 400)

    filename = str(uploaded_file.filename or "").strip()
    if not filename:
        return _error("Nom de fichier vide.", 400)

    settings = current_app.config["SETTINGS"]

    temp_dir = Path(settings.TEMP_DIR)
    temp_dir.mkdir(parents=True, exist_ok=True)

    safe_name = secure_filename(filename) or "upload.torrent"
    saved_path = temp_dir / f"{uuid4().hex}_{safe_name}"
    uploaded_file.save(saved_path)

    try:
        job, reused = service.create_torrent_file_job(
            context=ctx,
            uploaded_path=str(saved_path),
            provider_name=provider_name,
            provider_config_id=provider_config_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
        )

        item_error = None

        if auto_start and not reused:
            try:
                job = service.start_job(ctx, job.id)
            except Exception as exc:
                item_error = str(exc)

                job.status = "failed"
                job.error_message = item_error
                job.updated_at = now()
                service.job_repository.update_status_state(job)

        return jsonify({
            "job": serialize_job(job),
            "reused": reused,
            "error": item_error,
        }), 200 if reused else 201

    except Exception as exc:
        _safe_unlink(saved_path)
        return _handle_provider_exception(exc)


@jobs_v2_bp.get("")
def list_jobs_v2():
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    status = request.args.get("status")
    jobs = service.list_jobs(ctx, status=status)
    return jsonify([serialize_job(j) for j in jobs])


@jobs_v2_bp.get("/<job_id>")
def get_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    job = service.get_job(ctx, job_id)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/start")
def start_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    try:
        job = service.start_job(ctx, job_id)
    except Exception as exc:
        return _handle_provider_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/refresh")
def refresh_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    try:
        job = service.refresh_job(ctx, job_id)
    except Exception as exc:
        return _handle_provider_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/select-files")
def select_files_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    data = request.get_json(silent=True) or {}
    files = data.get("files")

    if not files:
        return _error("files is required")

    try:
        job = service.select_files(ctx, job_id, files)
    except Exception as exc:
        return _handle_provider_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/unrestrict")
def unrestrict_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    try:
        job = service.unrestrict_job(ctx, job_id)
    except Exception as exc:
        return _handle_provider_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/files/<int:file_id>/unrestrict")
def unrestrict_job_file_v2(job_id, file_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    try:
        job = service.unrestrict_file(ctx, job_id, file_id)
    except Exception as exc:
        return _handle_provider_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/send-to-destination")
def send_to_destination_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    data = request.get_json(silent=True) or {}
    destination_name = data.get("destination_name")
    destination_config_id = data.get("destination_config_id") or data.get("destination_id")

    if destination_name is not None and destination_name not in ALLOWED_DESTINATIONS:
        return _error("invalid destination_name")

    if destination_name == "links_only":
        return _error("links_only is not a real send destination")

    err = _check_local_space_permission(ctx, destination_config_id=destination_config_id, destination_name=destination_name)
    if err:
        return err

    try:
        job = service.send_to_destination(
            ctx,
            job_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
        )
    except Exception as exc:
        return _handle_destination_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/resend")
def resend_to_destination_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    data = request.get_json(silent=True) or {}
    destination_name = data.get("destination_name")
    destination_config_id = data.get("destination_config_id") or data.get("destination_id")

    if destination_name is not None and destination_name not in ALLOWED_DESTINATIONS:
        return _error("invalid destination_name")

    if destination_name == "links_only":
        return _error("links_only is not a real send destination")

    err = _check_local_space_permission(ctx, destination_config_id=destination_config_id, destination_name=destination_name)
    if err:
        return err

    try:
        job = service.resend_to_destination(
            ctx,
            job_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
        )
    except Exception as exc:
        return _handle_destination_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/destination/cancel")
def cancel_local_destination_download_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    try:
        job = service.cancel_local_download(ctx, job_id)
    except Exception as exc:
        return _handle_destination_exception(exc)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/clone-with-provider")
def clone_job_with_provider_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    data = request.get_json(silent=True) or {}

    provider_name = data.get("provider_name")
    provider_config_id = data.get("provider_config_id") or data.get("provider_id")
    destination_name = data.get("destination_name")
    destination_config_id = data.get("destination_config_id") or data.get("destination_id")
    auto_start = bool(data.get("auto_start", False))

    if not provider_name and not provider_config_id:
        return _error("provider_config_id or provider_name is required")

    if provider_name is not None and provider_name not in ALLOWED_PROVIDERS:
        return _error("invalid provider_name")

    if destination_name is not None and destination_name not in ALLOWED_DESTINATIONS:
        return _error("invalid destination_name")

    try:
        job, reused = service.clone_job_with_provider(
            context=ctx,
            job_id=job_id,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
            auto_start=auto_start,
        )

        return jsonify({
            "job": serialize_job(job),
            "reused": reused,
        }), 200 if reused else 201

    except Exception as exc:
        return _handle_provider_exception(exc)


@jobs_v2_bp.post("/<job_id>/restart")
def restart_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    try:
        job = service.restart_job(ctx, job_id)
    except ValueError as exc:
        return _error(str(exc), 400)
    except RuntimeError as exc:
        return _error(str(exc), 500)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.post("/<job_id>/cancel")
def cancel_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    try:
        job = service.cancel_job(ctx, job_id)
    except ValueError as exc:
        return _error(str(exc), 400)
    except RuntimeError as exc:
        return _error(str(exc), 500)

    if not job:
        return _error("Not found", 404)

    return jsonify(serialize_job(job))


@jobs_v2_bp.delete("/<job_id>")
def delete_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    deleted = service.delete_job(ctx, job_id)

    if not deleted:
        return _error("Not found", 404)

    return "", 204
