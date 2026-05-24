from datetime import UTC, datetime

from flask import current_app

from backend.services_v2.user_context import UserContext
from backend.routes_v2.qbittorrent_compat_support.security import _friendly_qbit_error
from backend.routes_v2.qbittorrent_compat_support.files import _save_uploaded_torrent, _safe_unlink


def _get_default_destination_config_id(ctx: UserContext) -> str | None:
    service = current_app.config.get("DESTINATION_CONFIG_SERVICE_V2")

    if not service:
        return None

    destination = service.get_default_destination_config(ctx)

    if not destination or not destination.is_enabled:
        return None

    return destination.id


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
