from flask import jsonify, request, current_app

from backend.services_v2.job_service import JobService
from backend.routes_v2._context import get_user_context

from backend.routes_v2.jobs_support.errors import (
    _error,
    _handle_provider_exception,
)

from backend.routes_v2.jobs_support.serialization import serialize_job


def register_lifecycle_job_routes(jobs_v2_bp):

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

    @jobs_v2_bp.post("/<job_id>/restart")
    def restart_job_v2(job_id):
        ctx = get_user_context()
        service: JobService = current_app.config["JOB_SERVICE_V2"]

        try:
            job = service.restart_job(ctx, job_id)
        except ValueError as exc:
            return _error(str(exc), 400)
        except Exception as exc:
            return _handle_provider_exception(exc)

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
