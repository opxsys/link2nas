import json
import time
from redis import Redis
from rq import Queue, Worker

from app import create_app
from config import Settings
from backend.services_v2.job_service import now
from backend.services_v2.destinations.local_destination import LocalDownloadCancelled


def _is_cancel_requested(job) -> bool:
    return str(job.destination_status or "").strip().lower() in {
        "cancel_requested",
        "cancelled",
    }


def perform_local_download_job(user_id: str, job_id: str, destination_config_id: str | None = None):
    app = create_app()

    with app.app_context():
        job_repository = app.config["JOB_REPOSITORY_V2"]
        destination_factory = app.config["USER_DESTINATION_FACTORY_V2"]

        job = job_repository.get_by_id(user_id, job_id)
        if not job:
            return

        if _is_cancel_requested(job):
            job.destination_status = "cancelled"
            job.destination_message = "Local download cancelled"
            job.sent_to_destination = False
            job.updated_at = now()
            job_repository.update_destination_state(job)
            return

        output_links = json.loads(job.output_links_json or "[]")
        if not isinstance(output_links, list) or not output_links:
            raise ValueError("Invalid output links")

        resolved = destination_factory.resolve_destination_for_user(
            user_id=user_id,
            destination_config_id=destination_config_id or job.destination_config_id,
            destination_name=job.destination_name if not destination_config_id else None,
        )

        if resolved.name != "local":
            raise ValueError("Local download worker only handles local destination")

        job.destination_config_id = resolved.destination_config_id
        job.destination_name = resolved.name
        job.destination_profile_name = resolved.destination_profile_name
        job.send_to_destination = True
        job.destination_status = "downloading"
        job.destination_message = "Downloading to local destination"
        job.destination_message_key = None
        job.destination_message_params = None
        job.destination_progress = 0
        job.destination_last_attempt = now()
        job.updated_at = now()
        job.error_message = None
        job_repository.update_destination_state(job)

        def cancel_check() -> bool:
            latest = job_repository.get_by_id(user_id, job_id)
            return bool(latest and _is_cancel_requested(latest))

        required_bytes = resolved.destination._required_bytes(output_links)

        downloaded_total = 0
        last_progress_update = 0.0


        def progress_callback(chunk_size, file_downloaded, file_total):
            nonlocal downloaded_total, last_progress_update, job


            downloaded_total += int(chunk_size or 0)

            if required_bytes <= 0:
                return

            progress = int((downloaded_total / required_bytes) * 100)
            progress = max(0, min(progress, 99))

            current_time = time.time()

            if progress <= int(job.destination_progress or 0):
                return            

            if current_time - last_progress_update < 1.0 and progress < 99:
                return

            latest = job_repository.get_by_id(user_id, job_id)
            if not latest:
                return

            if _is_cancel_requested(latest):
                raise LocalDownloadCancelled("Local download cancelled")

            latest.destination_progress = progress
            latest.destination_status = "downloading"
            latest.destination_message = f"Downloading to local destination ({progress}%)"
            latest.updated_at = now()


            job_repository.update_destination_state(latest)


            job = latest
            last_progress_update = current_time

        try:

            result = resolved.destination.send(
                output_links,
                cancel_check=cancel_check,
                progress_callback=progress_callback,
            ) or {}

            job = job_repository.get_by_id(user_id, job_id)
            if not job:
                return

            if _is_cancel_requested(job):
                raise LocalDownloadCancelled("Local download cancelled")

            job.status = "completed"
            job.sent_to_destination = True
            job.sent_to_destination_at = now()
            job.destination_progress = 100
            job.destination_status = "sent"
            job.destination_message = "Sent to local destination"
            job.destination_path = result.get("destination_path") or job.destination_path
            job.completed_at = job.completed_at or now()
            job.updated_at = now()
            job.error_message = None
            job_repository.update_destination_state(job)

        except LocalDownloadCancelled:
            job = job_repository.get_by_id(user_id, job_id)
            if not job:
                return

            job.destination_status = "cancelled"
            job.destination_message = "Local download cancelled"
            job.sent_to_destination = False
            job.send_to_destination = False
            job.destination_progress = 0
            job.updated_at = now()
            job_repository.update_destination_state(job)

        except Exception as exc:
            job = job_repository.get_by_id(user_id, job_id)
            if not job:
                raise

            job.destination_status = "failed"
            job.destination_message = str(exc)
            job.error_message = str(exc)
            job.updated_at = now()
            job_repository.update_destination_state(job)
            raise

def main() -> None:

    settings = Settings()

    app = create_app()

    with app.app_context():
        app_settings_service = app.config["APP_SETTINGS_SERVICE_V2"]
        local_worker_settings = app_settings_service.get_local_download_worker_settings()

    if not bool(local_worker_settings.get("enabled", True)):
        print("[V2_LOCAL_DOWNLOAD_WORKER_DISABLED] downloads.local_worker.enabled=false")
        return

    print(
        "[V2_LOCAL_DOWNLOAD_WORKER_START] "
        f"queue={settings.RQ_LOCAL_DOWNLOAD_QUEUE_NAME} "
        f"max_concurrent_downloads={local_worker_settings.get('max_concurrent_downloads')} "
        f"poll_interval_seconds={local_worker_settings.get('poll_interval_seconds')}"
    )

    redis_conn = Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=False,
    )

    queue = Queue(settings.RQ_LOCAL_DOWNLOAD_QUEUE_NAME, connection=redis_conn)
    worker = Worker([queue], connection=redis_conn)
    worker.work()


if __name__ == "__main__":
    main()
