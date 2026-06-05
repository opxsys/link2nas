import logging

from flask import jsonify, request, current_app

from backend.utils.time import utc_now_iso as now
from backend.services_v2.job_service import JobService
from backend.routes_v2._context import get_user_context

from backend.routes_v2.jobs_support.errors import (
    _error,
    _handle_provider_exception,
    is_persistable_provider_error,
    safe_provider_error_message,
    PROVIDER_ERROR_STATUS,
)

from backend.routes_v2.jobs_support.serialization import serialize_job


logger = logging.getLogger(__name__)


def _persist_job_failed(service: "JobService", ctx, job_id: str, safe_msg: str) -> None:
    """Fetch the job and persist it as failed with a safe error message."""
    try:
        job = service.job_repository.get_by_id(ctx.user_id, job_id)
        if job is not None:
            job.status = "failed"
            job.error_message = safe_msg
            job.updated_at = now()
            service.job_repository.update_status_state(job)
    except Exception:
        logger.exception("Failed to persist failed state for job %s", job_id)


def _handle_start_exception(service: "JobService", ctx, job_id: str, exc: Exception):
    """Handle exceptions from start/restart, persisting failed for expected content errors."""
    if is_persistable_provider_error(exc):
        safe_msg = safe_provider_error_message(exc)
        _persist_job_failed(service, ctx, job_id, safe_msg)
        return _error(safe_msg, PROVIDER_ERROR_STATUS)
    return _handle_provider_exception(exc)


def register_lifecycle_job_routes(jobs_v2_bp):

    @jobs_v2_bp.post("/<job_id>/start")
    def start_job_v2(job_id):
        ctx = get_user_context()
        service: JobService = current_app.config["JOB_SERVICE_V2"]

        try:
            job = service.start_job(ctx, job_id)
        except Exception as exc:
            return _handle_start_exception(service, ctx, job_id, exc)

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

    @jobs_v2_bp.post("/<job_id>/restart")
    def restart_job_v2(job_id):
        ctx = get_user_context()
        service: JobService = current_app.config["JOB_SERVICE_V2"]

        try:
            job = service.restart_job(ctx, job_id)
        except ValueError as exc:
            return _error(str(exc), 400)
        except Exception as exc:
            return _handle_start_exception(service, ctx, job_id, exc)

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
