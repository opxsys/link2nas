from flask import jsonify, request, current_app

from backend.services_v2.job_service import JobService
from backend.routes_v2._context import get_user_context

from backend.routes_v2.jobs_support.errors import (
    _error,
    _handle_destination_exception,
)

from backend.routes_v2.jobs_support.serialization import serialize_job

from backend.routes_v2.jobs_support.request_validation import (
    _check_local_space_permission,
    validate_destination_name,
)


def register_destination_job_routes(jobs_v2_bp):

    @jobs_v2_bp.post("/<job_id>/send-to-destination")
    def send_to_destination_v2(job_id):
        ctx = get_user_context()
        service: JobService = current_app.config["JOB_SERVICE_V2"]

        data = request.get_json(silent=True) or {}
        destination_name = data.get("destination_name")
        destination_config_id = data.get("destination_config_id") or data.get("destination_id")

        if err := validate_destination_name(destination_name):
            return err

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

        if err := validate_destination_name(destination_name):
            return err

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
