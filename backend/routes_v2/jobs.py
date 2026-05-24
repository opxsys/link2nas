import json
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
    _parse_json_object,
    _filename_from_path,
)

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


def _parse_output_links(job) -> list[dict]:
    try:
        if not job.output_links_json:
            return []

        parsed = json.loads(job.output_links_json)

        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]

        return []
    except Exception:
        return []


def _parse_provider_payload(job) -> dict:
    try:
        if not job.provider_payload_json:
            return {}

        parsed = json.loads(job.provider_payload_json)

        if isinstance(parsed, dict):
            return parsed

        return {}
    except Exception:
        return {}


def _active_provider_configs(ctx) -> list[dict]:
    factory = current_app.config.get("USER_PROVIDER_FACTORY_V2")
    if not factory:
        return []

    try:
        configs = factory.list_enabled_provider_configs_for_user(ctx.user_id)
    except Exception:
        return []

    return [
        {
            "id": config.id,
            "name": config.name,
            "provider_type": config.provider_type,
            "provider_name": config.provider_type,
            "is_default": config.is_default,
        }
        for config in configs
    ]


def _active_provider_names(ctx) -> list[str]:
    names = []

    for config in _active_provider_configs(ctx):
        provider_name = config.get("provider_type") or config.get("provider_name")
        if provider_name and provider_name not in names:
            names.append(provider_name)

    return names


def _active_real_destination_configs(ctx) -> list[dict]:
    factory = current_app.config.get("USER_DESTINATION_FACTORY_V2")
    if factory:
        try:
            configs = factory.list_enabled_destination_configs_for_user(ctx.user_id)
        except Exception:
            configs = []
    else:
        service = current_app.config.get("DESTINATION_CONFIG_SERVICE_V2")
        if not service:
            return []

        try:
            configs = service.list_destination_configs(ctx)
        except Exception:
            return []

        configs = [config for config in configs if config.is_enabled]

    result = []

    for config in configs:
        destination_type = "synology" if config.destination_type == "nas" else config.destination_type

        if destination_type not in {"synology", "local"}:
            continue

        result.append({
            "id": config.id,
            "name": config.name,
            "destination_type": destination_type,
            "destination_name": destination_type,
            "is_default": config.is_default,
        })

    return result


def _active_real_destination_names(ctx) -> list[str]:
    names = []

    for config in _active_real_destination_configs(ctx):
        destination_name = config.get("destination_type") or config.get("destination_name")
        if destination_name and destination_name not in names:
            names.append(destination_name)

    return names


def _serialize(job):
    ctx = get_user_context()
    service: JobService | None = current_app.config.get("JOB_SERVICE_V2")
    allowed_actions = service.get_allowed_actions(job) if service else []

    output_links = _parse_output_links(job)
    provider_payload = _parse_provider_payload(job)

    first_link = output_links[0] if output_links else {}

    provider_files = provider_payload.get("files") or []
    if not isinstance(provider_files, list):
        provider_files = []

    links_by_file_id = {}
    links_by_index = {}

    for index, link in enumerate(output_links, start=1):
        if not isinstance(link, dict):
            continue

        file_id = link.get("file_id") or index
        links_by_file_id[str(file_id)] = link
        links_by_index[index] = link

    serialized_files = []

    if provider_files:
        for index, item in enumerate(provider_files, start=1):
            if not isinstance(item, dict):
                continue

            file_id = item.get("id") or index
            link = links_by_file_id.get(str(file_id)) or links_by_index.get(index) or {}

            path = (
                item.get("path")
                or item.get("filename")
                or item.get("name")
                or link.get("relative_path")
                or link.get("path")
                or link.get("filename")
            )

            filename = (
                item.get("filename")
                or item.get("name")
                or link.get("filename")
                or _filename_from_path(path)
            )

            serialized_files.append({
                "id": file_id,
                "path": path,
                "filename": filename,
                "bytes": item.get("bytes") or item.get("filesize") or item.get("size") or link.get("filesize"),
                "filesize": item.get("filesize") or item.get("bytes") or item.get("size") or link.get("filesize"),
                "debrid_link": link.get("debrid_link") or item.get("link") or item.get("debrid_link"),
                "download_url": link.get("url") or item.get("download_url"),
            })

    elif output_links:
        for index, item in enumerate(output_links, start=1):
            path = item.get("relative_path") or item.get("path") or item.get("filename") or f"file_{index}"
            serialized_files.append({
                "id": item.get("file_id") or index,
                "path": path,
                "filename": item.get("filename") or _filename_from_path(path),
                "bytes": item.get("filesize"),
                "filesize": item.get("filesize"),
                "debrid_link": item.get("debrid_link"),
                "download_url": item.get("url"),
            })

    filename = (
        provider_payload.get("filename")
        or provider_payload.get("name")
        or first_link.get("filename")
        or None
    )

    filesize = (
        provider_payload.get("bytes")
        or provider_payload.get("filesize")
        or provider_payload.get("size")
        or first_link.get("filesize")
        or None
    )

    progress = provider_payload.get("progress")
    if progress is None:
        progress = 100 if job.status in {"downloaded", "ready", "completed"} else 0

    is_per_file = job.output_mode == "per_file" or len(output_links) > 1

    download_url = None if is_per_file else first_link.get("url")
    debrid_link = None

    provider_links = provider_payload.get("links")
    if not is_per_file and isinstance(provider_links, list) and provider_links:
        debrid_link = provider_links[0]

    destination_type = job.destination_name

    active_provider_configs = _active_provider_configs(ctx)
    active_real_destination_configs = _active_real_destination_configs(ctx)

    active_provider_names = _active_provider_names(ctx)
    active_real_destination_names = _active_real_destination_names(ctx)

    active_provider_config_ids = {
        str(config.get("id"))
        for config in active_provider_configs
        if config.get("id")
    }

    active_destination_config_ids = {
        str(config.get("id"))
        for config in active_real_destination_configs
        if config.get("id")
    }

    provider_available = (
        (job.provider_config_id and str(job.provider_config_id) in active_provider_config_ids)
        or job.provider_name in active_provider_names
    )

    destination_available = (
        not job.destination_config_id
        or str(job.destination_config_id) in active_destination_config_ids
        or not job.destination_name
        or job.destination_name in active_real_destination_names
    )
    return {
        "id": job.id,
        "source_type": job.source_type,
        "source_value": job.source_value,
        "status": job.status,
        "allowed_actions": allowed_actions,

        "provider_config_id": job.provider_config_id,
        "provider_name": job.provider_name,
        "provider_type": job.provider_name,
        "provider_profile_name": job.provider_profile_name,
        "provider_resource_id": job.provider_resource_id,
        "provider_status": job.provider_status,
        "provider_payload_json": job.provider_payload_json,
        "provider_available": provider_available,
        "destination_available": destination_available,

        "destination_config_id": job.destination_config_id,
        "destination_name": job.destination_name,
        "destination_type": destination_type,
        "destination_profile_name": job.destination_profile_name,

        "output_mode": "per_file" if is_per_file else job.output_mode,
        "output_links_json": job.output_links_json,
        "output_links": output_links,
        "unrestricted_at": job.unrestricted_at,

        "error_message": job.error_message,

        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "cancelled_at": job.cancelled_at,

        "torrent_id": job.provider_resource_id,
        "torrent_status": job.provider_status,
        "selected_files": None,

        "filename": filename,
        "filesize": filesize,
        "progress": progress,
        "download_url": download_url,
        "debrid_link": debrid_link,
        "download_id": first_link.get("provider_download_id"),

        "files": serialized_files,

        "send_to_destination": bool(job.send_to_destination),
        "sent_to_destination": bool(job.sent_to_destination),
        "destination_status": job.destination_status,
        "destination_message": job.destination_message,
        "destination_message_key": job.destination_message_key,
        "destination_message_params": _parse_json_object(job.destination_message_params),
        "destination_last_attempt": job.destination_last_attempt,
        "sent_to_destination_at": job.sent_to_destination_at,
        "destination_path": job.destination_path,
        "destination_progress": int(job.destination_progress or 0),

        "active_provider_names": active_provider_names,
        "active_provider_configs": active_provider_configs,
        "active_real_destination_names": active_real_destination_names,
        "active_real_destination_configs": active_real_destination_configs,
        "can_clone_with_other_provider": len([
            p for p in active_provider_configs
            if p.get("id") != job.provider_config_id
        ]) >= 1,
        "can_send_to_other_destination": len(active_real_destination_configs) >= 1,

        "last_message": job.error_message,
        "last_message_key": None,
        "last_message_params": None,
    }


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

        return jsonify(_serialize(job)), 201

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
                "job": _serialize(job),
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
            "job": _serialize(job),
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
    return jsonify([_serialize(j) for j in jobs])


@jobs_v2_bp.get("/<job_id>")
def get_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    job = service.get_job(ctx, job_id)

    if not job:
        return _error("Not found", 404)

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))

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

    return jsonify(_serialize(job))

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
            "job": _serialize(job),
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

    return jsonify(_serialize(job))


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

    return jsonify(_serialize(job))


@jobs_v2_bp.delete("/<job_id>")
def delete_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    deleted = service.delete_job(ctx, job_id)

    if not deleted:
        return _error("Not found", 404)

    return "", 204