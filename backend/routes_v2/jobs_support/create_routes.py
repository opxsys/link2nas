from pathlib import Path
from uuid import uuid4

from flask import jsonify, request, current_app
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
    safe_provider_error_message,
)

from backend.routes_v2.jobs_support.helpers import (
    _bool_from_form,
    _safe_unlink,
)

from backend.routes_v2.jobs_support.serialization import serialize_job

from backend.routes_v2.jobs_support.request_validation import (
    ALLOWED_SOURCE_TYPES,
    _check_local_space_permission,
    _resolve_destination_ref_for_request,
    validate_provider_name,
    validate_destination_name,
)


def register_create_job_routes(jobs_v2_bp):

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

        if err := validate_provider_name(provider_name):
            return err

        if err := validate_destination_name(destination_name):
            return err

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

        if err := validate_provider_name(provider_name):
            return err

        if err := validate_destination_name(destination_name):
            return err

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
                    item_error = safe_provider_error_message(exc)

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

        if err := validate_provider_name(provider_name):
            return err

        if err := validate_destination_name(destination_name):
            return err

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
                    item_error = safe_provider_error_message(exc)

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
