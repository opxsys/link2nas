from flask import Blueprint, jsonify, request, current_app

from backend.services_v2.job_service import JobService
from backend.routes_v2._context import get_user_context

from backend.routes_v2.jobs_support.errors import (
    _error,
    _handle_provider_exception,
)

from backend.routes_v2.jobs_support.serialization import serialize_job

from backend.routes_v2.jobs_support.request_validation import (
    validate_provider_name,
    validate_destination_name,
)

from backend.routes_v2.jobs_support.create_routes import register_create_job_routes
from backend.routes_v2.jobs_support.destination_routes import register_destination_job_routes
from backend.routes_v2.jobs_support.lifecycle_routes import register_lifecycle_job_routes

jobs_v2_bp = Blueprint("jobs_v2", __name__, url_prefix="/api/v2/jobs")

register_create_job_routes(jobs_v2_bp)
register_destination_job_routes(jobs_v2_bp)
register_lifecycle_job_routes(jobs_v2_bp)


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

    if err := validate_provider_name(provider_name):
        return err

    if err := validate_destination_name(destination_name):
        return err

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


@jobs_v2_bp.delete("/<job_id>")
def delete_job_v2(job_id):
    ctx = get_user_context()
    service: JobService = current_app.config["JOB_SERVICE_V2"]

    deleted = service.delete_job(ctx, job_id)

    if not deleted:
        return _error("Not found", 404)

    return "", 204
