import json
from pathlib import Path
from datetime import UTC, datetime
from backend.utils.time import utc_now_iso

from redis import Redis
from rq import Queue
from flask import current_app

from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.status_actions import ACTION_RULES, map_provider_status
from backend.services_v2.job_support.source_helpers import filename_from_path
from backend.services_v2.job_support.notifications import (
    emit_notification_event,
    emit_provider_failed,
)
from backend.services_v2.job_support.config_resolution import (
    resolve_provider_config,
    resolve_destination_config,
)
from backend.services_v2.job_support.creation import (
    create_job_impl,
    create_jobs_from_lines_impl,
    create_torrent_file_job_impl,
    clone_job_with_provider_impl,
)
from backend.services_v2.job_support.link_health import links_expired_or_invalid
from backend.services_v2.job_support.restart_policy import (
    get_restart_cooldown_seconds,
    ensure_restart_cooldown_elapsed,
)
from backend.services_v2.job_support.provider_cleanup import (
    delete_provider_resources_best_effort,
    is_unknown_resource_error,
)

now = utc_now_iso


class JobService:
    def __init__(
        self,
        job_repository,
        provider_factory=None,
        destination_factory=None,
        app_settings_service=None,
        notification_service=None,
    ):
        self.job_repository = job_repository
        self.provider_factory = provider_factory
        self.destination_factory = destination_factory
        self.app_settings_service = app_settings_service
        self.notification_service = notification_service

    def get_allowed_actions(self, job: Job) -> list[str]:
        return ACTION_RULES.get(job.status, [])

    def _ensure_action_allowed(self, job: Job, action: str) -> None:
        allowed = self.get_allowed_actions(job)

        if action not in allowed:
            raise ValueError(
                f"Action '{action}' is not allowed from status '{job.status}'"
            )

    def _emit_notification_event(
        self,
        job: Job,
        *,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        payload: dict | None = None,
    ) -> None:
        emit_notification_event(
            self.notification_service,
            job,
            event_type=event_type,
            severity=severity,
            title=title,
            message=message,
            payload=payload,
        )

    def _emit_provider_failed(self, job: Job, exc: Exception) -> None:
        emit_provider_failed(self.notification_service, job, exc)

    def _resolve_provider_config(
        self,
        context: UserContext,
        provider_name: str | None = None,
        provider_config_id: str | None = None,
    ):
        return resolve_provider_config(
            self.provider_factory,
            context,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
        )

    def _resolve_destination_config(
        self,
        context: UserContext,
        destination_name: str | None = None,
        destination_config_id: str | None = None,
        *,
        allow_none: bool = True,
    ):
        return resolve_destination_config(
            self.destination_factory,
            context,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
            allow_none=allow_none,
        )

    def create_job(
        self,
        context: UserContext,
        source_type: str,
        source_value: str,
        provider_name: str | None = None,
        destination_name: str | None = None,
        *,
        provider_config_id: str | None = None,
        destination_config_id: str | None = None,
    ) -> Job:
        return create_job_impl(
            self,
            context,
            source_type,
            source_value,
            provider_name=provider_name,
            destination_name=destination_name,
            provider_config_id=provider_config_id,
            destination_config_id=destination_config_id,
        )

    def create_jobs_from_lines(
        self,
        context: UserContext,
        raw_text: str,
        provider_name: str | None = None,
        destination_name: str | None = None,
        *,
        provider_config_id: str | None = None,
        destination_config_id: str | None = None,
    ) -> list[tuple[Job, bool]]:
        return create_jobs_from_lines_impl(
            self,
            context,
            raw_text,
            provider_name=provider_name,
            destination_name=destination_name,
            provider_config_id=provider_config_id,
            destination_config_id=destination_config_id,
        )

    def create_torrent_file_job(
        self,
        context: UserContext,
        uploaded_path: str,
        provider_name: str | None = None,
        destination_name: str | None = None,
        *,
        provider_config_id: str | None = None,
        destination_config_id: str | None = None,
    ) -> tuple[Job, bool]:
        return create_torrent_file_job_impl(
            self,
            context,
            uploaded_path,
            provider_name=provider_name,
            destination_name=destination_name,
            provider_config_id=provider_config_id,
            destination_config_id=destination_config_id,
        )

    def clone_job_with_provider(
        self,
        context: UserContext,
        job_id: str,
        provider_name: str | None = None,
        destination_name: str | None = None,
        auto_start: bool = False,
        *,
        provider_config_id: str | None = None,
        destination_config_id: str | None = None,
    ) -> tuple[Job, bool]:
        return clone_job_with_provider_impl(
            self,
            context,
            job_id,
            provider_name=provider_name,
            destination_name=destination_name,
            auto_start=auto_start,
            provider_config_id=provider_config_id,
            destination_config_id=destination_config_id,
        )

    def get_job(self, context: UserContext, job_id: str) -> Job | None:
        return self.job_repository.get_by_id(context.user_id, job_id)

    def list_jobs(self, context: UserContext, status: str | None = None) -> list[Job]:
        jobs = self.job_repository.list_for_user(context.user_id)

        if status:
            wanted = str(status).strip().lower()
            jobs = [
                job
                for job in jobs
                if str(job.status or "").strip().lower() == wanted
            ]

        return jobs

    def start_job(self, context: UserContext, job_id: str) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        self._ensure_action_allowed(job, "start")

        if self.provider_factory is None:
            raise RuntimeError("Provider factory is not configured")

        resolved_provider = self.provider_factory.resolve_provider_for_user(
            user_id=context.user_id,
            provider_config_id=job.provider_config_id,
            provider_name=job.provider_name,
        )
        provider = resolved_provider.provider

        job.provider_config_id = resolved_provider.provider_config_id
        job.provider_name = resolved_provider.provider_type
        job.provider_profile_name = resolved_provider.provider_profile_name

        if job.source_type == "magnet":
            try:
                result = provider.add_magnet(job.source_value)
            except Exception as exc:
                self._emit_provider_failed(job, exc)
                raise

            return self._set_started_provider_job(job, result)

        if job.source_type == "torrent_file":
            torrent_hash = str(job.source_value).replace("torrent:", "", 1)
            torrent_path = Path("data/torrents") / f"{torrent_hash}.torrent"

            if not torrent_path.exists():
                raise ValueError("Torrent file content is no longer available")

            try:
                result = provider.add_torrent_file(str(torrent_path))
            except Exception as exc:
                self._emit_provider_failed(job, exc)
                raise

            return self._set_started_provider_job(job, result)

        if job.source_type == "direct_link":
            try:
                result = provider.unrestrict_link(job.source_value)
            except Exception as exc:
                self._emit_provider_failed(job, exc)
                raise

            download_url = result.get("download")

            if not download_url:
                raise ValueError("Provider returned no download URL")

            output_links = [
                {
                    "url": download_url,
                    "filename": result.get("filename"),
                    "filesize": result.get("filesize"),
                    "provider_download_id": result.get("id"),
                    "relative_path": result.get("filename"),
                    "path": result.get("filename"),
                }
            ]

            timestamp = now()

            job.provider_status = "unrestricted"
            job.provider_payload_json = json.dumps(result)
            job.output_mode = "single"
            job.output_links_json = json.dumps(output_links)
            job.status = "ready"
            job.started_at = timestamp
            job.unrestricted_at = timestamp
            job.updated_at = timestamp
            job.error_message = None

            self.job_repository.update_provider_state(job)
            self.job_repository.update_unrestrict_state(job)

            self._emit_notification_event(
                job,
                event_type="job.started",
                severity="info",
                title="Job started",
                message="Job has started.",
            )

            self._emit_notification_event(
                job,
                event_type="job.ready",
                severity="info",
                title="Job ready",
                message="Job direct link is ready.",
            )

            self._emit_notification_event(
                job,
                event_type="job.links_ready",
                severity="info",
                title="Links ready",
                message="Direct links are available for this job.",
            )

            return job

        raise ValueError("Unsupported source_type")

    def _set_started_provider_job(self, job: Job, result: dict) -> Job:
        timestamp = now()

        job.provider_resource_id = str(result.get("id")) if result.get("id") else None
        job.provider_status = "submitted"
        job.provider_payload_json = json.dumps(result)
        job.status = "started"
        job.started_at = timestamp
        job.updated_at = timestamp
        job.error_message = None

        self.job_repository.update_provider_state(job)

        self._emit_notification_event(
            job,
            event_type="job.started",
            severity="info",
            title="Job started",
            message="Job has started.",
        )

        return job

    def _resolve_files_to_select(self, provider_payload: dict) -> str:
        files = provider_payload.get("files") or []

        ids = []

        for index, item in enumerate(files, start=1):
            if isinstance(item, dict):
                file_id = item.get("id") or item.get("file_id") or index
            else:
                file_id = index

            ids.append(str(file_id))

        if ids:
            return ",".join(ids)

        return "all"

    def refresh_job(self, context: UserContext, job_id: str) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        self._ensure_action_allowed(job, "refresh")

        if not job.provider_resource_id:
            raise ValueError("Job has no provider_resource_id")

        if self.provider_factory is None:
            raise RuntimeError("Provider factory is not configured")

        provider = self.provider_factory.get_provider_for_user(
            user_id=context.user_id,
            provider_config_id=job.provider_config_id,
            provider_name=job.provider_name,
        )

        try:
            info = provider.get_torrent_info(job.provider_resource_id)
        except Exception as exc:
            self._emit_provider_failed(job, exc)
            raise

        provider_status = info.get("status")

        if provider_status == "waiting_files_selection":
            files_to_select = self._resolve_files_to_select(info)

            try:
                provider.select_files(job.provider_resource_id, files_to_select)
            except Exception as exc:
                self._emit_provider_failed(job, exc)
                raise

            job.status = "downloading"
            job.provider_status = "files_selected"
            job.provider_payload_json = json.dumps(info)
            job.updated_at = now()
            job.error_message = None

            self.job_repository.update_after_select_files(job)
            return job

        job.provider_status = provider_status
        job.provider_payload_json = json.dumps(info)
        job.status = map_provider_status(provider_status)
        job.updated_at = now()
        job.error_message = None

        if job.status == "downloaded":
            job.completed_at = now()
            self.job_repository.update_refresh_state(job)

            job = self.unrestrict_job(context, job.id)

            if job and job.send_to_destination:
                job = self.send_to_destination(context, job.id)

            return job

        self.job_repository.update_refresh_state(job)
        return job

    def select_files(
        self,
        context: UserContext,
        job_id: str,
        files: str,
    ) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        self._ensure_action_allowed(job, "select_files")

        if not job.provider_resource_id:
            raise ValueError("Job has no provider_resource_id")

        if not files:
            raise ValueError("files is required")

        if self.provider_factory is None:
            raise RuntimeError("Provider factory is not configured")

        provider = self.provider_factory.get_provider_for_user(
            user_id=context.user_id,
            provider_config_id=job.provider_config_id,
            provider_name=job.provider_name,
        )

        try:
            provider.select_files(job.provider_resource_id, files)
        except Exception as exc:
            self._emit_provider_failed(job, exc)
            raise

        job.status = "downloading"
        job.provider_status = "files_selected"
        job.updated_at = now()
        job.error_message = None

        self.job_repository.update_after_select_files(job)
        return job

    def unrestrict_job(self, context: UserContext, job_id: str) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        if job.status not in {"downloaded", "ready", "completed"}:
            self._ensure_action_allowed(job, "unrestrict")

        previous_status = str(job.status or "").strip().lower()
        had_links = bool(json.loads(job.output_links_json or "[]"))

        try:
            output_links = self._build_output_links(context, job)
        except Exception as exc:
            self._emit_provider_failed(job, exc)
            raise

        job.output_mode = "single" if len(output_links) == 1 else "per_file"
        job.output_links_json = json.dumps(output_links)
        job.status = "ready" if job.status != "completed" else "completed"
        job.unrestricted_at = now()
        job.updated_at = now()
        job.error_message = None

        self.job_repository.update_unrestrict_state(job)

        if previous_status != "ready" and job.status == "ready":
            self._emit_notification_event(
                job,
                event_type="job.ready",
                severity="info",
                title="Job ready",
                message="Job direct links are ready.",
            )

        if output_links and not had_links:
            self._emit_notification_event(
                job,
                event_type="job.links_ready",
                severity="info",
                title="Links ready",
                message="Direct links are available for this job.",
            )

        return job

    def unrestrict_file(self, context: UserContext, job_id: str, file_id: int) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        payload = json.loads(job.provider_payload_json or "{}")
        links = payload.get("links") or []
        files = payload.get("files") or []

        index = int(file_id) - 1

        if index < 0 or index >= len(links):
            raise ValueError("Invalid file id")

        if self.provider_factory is None:
            raise RuntimeError("Provider factory is not configured")

        provider = self.provider_factory.get_provider_for_user(
            user_id=context.user_id,
            provider_config_id=job.provider_config_id,
            provider_name=job.provider_name,
        )

        existing_links = json.loads(job.output_links_json or "[]")
        if not isinstance(existing_links, list):
            existing_links = []

        while len(existing_links) < len(links):
            existing_links.append({})

        link = links[index]
        file_meta = files[index] if index < len(files) and isinstance(files[index], dict) else {}

        try:
            result = provider.unrestrict_link(link)
        except Exception as exc:
            self._emit_provider_failed(job, exc)
            raise

        download_url = result.get("download")

        if not download_url:
            raise ValueError("Provider returned no download URL")

        relative_path = file_meta.get("path") or result.get("filename")
        filename = result.get("filename") or filename_from_path(relative_path)

        had_links = any(item for item in existing_links if item)

        existing_links[index] = {
            "url": download_url,
            "filename": filename,
            "filesize": result.get("filesize") or file_meta.get("bytes"),
            "provider_download_id": result.get("id"),
            "debrid_link": link,
            "file_id": file_meta.get("id") or file_id,
            "relative_path": relative_path,
            "path": relative_path,
        }

        previous_status = str(job.status or "").strip().lower()
        compact_links = [item for item in existing_links if item]

        job.output_mode = "single" if len(compact_links) == 1 else "per_file"
        job.output_links_json = json.dumps(compact_links)
        job.status = "ready" if job.status != "completed" else "completed"
        job.unrestricted_at = now()
        job.updated_at = now()
        job.error_message = None

        self.job_repository.update_unrestrict_state(job)

        if previous_status != "ready" and job.status == "ready":
            self._emit_notification_event(
                job,
                event_type="job.ready",
                severity="info",
                title="Job ready",
                message="Job direct links are ready.",
            )

        if compact_links and not had_links:
            self._emit_notification_event(
                job,
                event_type="job.links_ready",
                severity="info",
                title="Links ready",
                message="Direct links are available for this job.",
            )

        return job

    def _build_output_links(self, context: UserContext, job: Job) -> list[dict]:
        payload = json.loads(job.provider_payload_json or "{}")
        links = payload.get("links") or []
        files = payload.get("files") or []

        if not links and job.source_type == "direct_link":
            links = [job.source_value]

        if not links:
            raise ValueError("No provider links available")

        if self.provider_factory is None:
            raise RuntimeError("Provider factory is not configured")

        provider = self.provider_factory.get_provider_for_user(
            user_id=context.user_id,
            provider_config_id=job.provider_config_id,
            provider_name=job.provider_name,
        )

        output_links = []

        for index, link in enumerate(links):
            file_meta = files[index] if index < len(files) and isinstance(files[index], dict) else {}

            result = provider.unrestrict_link(link)
            download_url = result.get("download")

            if not download_url:
                raise ValueError("Provider returned no download URL")

            relative_path = file_meta.get("path") or result.get("filename")
            filename = result.get("filename") or filename_from_path(relative_path)

            output_links.append({
                "url": download_url,
                "filename": filename,
                "filesize": result.get("filesize") or file_meta.get("bytes"),
                "provider_download_id": result.get("id"),
                "debrid_link": link,
                "file_id": file_meta.get("id") or index + 1,
                "relative_path": relative_path,
                "path": relative_path,
            })

        return output_links

    def _enqueue_local_download(
        self,
        context: UserContext,
        job: Job,
        destination_config_id: str | None,
    ) -> None:
        settings = current_app.config["SETTINGS"]

        redis_conn = Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=False,
        )

        queue = Queue(
            settings.RQ_LOCAL_DOWNLOAD_QUEUE_NAME,
            connection=redis_conn,
        )

        queue.enqueue(
            "backend.services_v2.local_download_worker.perform_local_download_job",
            context.user_id,
            job.id,
            destination_config_id,
            job_timeout="24h",
            result_ttl=3600,
            failure_ttl=86400,
        )

    def send_to_destination(
        self,
        context: UserContext,
        job_id: str,
        destination_name: str | None = None,
        *,
        destination_config_id: str | None = None,
    ) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        previous_status = str(job.status or "").strip().lower()

        if job.status not in {"ready", "partially_ready", "completed"}:
            self._ensure_action_allowed(job, "send_to_destination")

        output_links = json.loads(job.output_links_json or "[]")

        if not isinstance(output_links, list) or not output_links:
            raise ValueError("Invalid output links")

        if self.destination_factory is None:
            raise RuntimeError("Destination factory is not configured")

        resolved = self.destination_factory.resolve_destination_for_user(
            user_id=context.user_id,
            destination_config_id=destination_config_id or job.destination_config_id,
            destination_name=destination_name if destination_config_id is None else None,
        )

        job.destination_config_id = resolved.destination_config_id
        job.destination_name = resolved.name
        job.destination_profile_name = resolved.destination_profile_name
        job.send_to_destination = True
        job.destination_message_key = None
        job.destination_message_params = None
        job.destination_last_attempt = now()
        job.updated_at = now()

        if resolved.name != "local":
            job.destination_status = "sending"
            job.destination_message = "Sending to destination"
            job.destination_message_key = None
            job.destination_message_params = None
            job.destination_progress = 0
            job.sent_to_destination = False
            job.sent_to_destination_at = None
            job.error_message = None
            self.job_repository.update_destination_state(job)

        try:
            self._attach_job_metadata_to_output_links(job, output_links)
            job.output_links_json = json.dumps(output_links)

            if resolved.name == "local":
                settings = current_app.config["SETTINGS"]

                current_status = str(job.destination_status or "").strip().lower()

                if current_status in {"queued", "downloading", "cancel_requested"}:
                    return job

                resolved.destination.ensure_enough_space(
                    output_links,
                    margin_percent=settings.LOCAL_DOWNLOAD_SPACE_MARGIN_PERCENT,
                    min_free_bytes=settings.LOCAL_DOWNLOAD_MIN_FREE_BYTES,
                )

                job.destination_status = "queued"
                job.destination_message = "Local download queued"
                job.destination_message_key = None
                job.destination_message_params = None
                job.sent_to_destination = False
                job.sent_to_destination_at = None
                job.destination_last_attempt = now()
                job.error_message = None
                job.updated_at = now()

                self.job_repository.update_unrestrict_state(job)
                self.job_repository.update_destination_state(job)

                self._enqueue_local_download(
                    context=context,
                    job=job,
                    destination_config_id=resolved.destination_config_id,
                )

                return job

            result = resolved.destination.send(output_links) or {}

            job.status = "completed"
            job.sent_to_destination = True
            job.sent_to_destination_at = now()
            job.destination_status = "sent"
            job.destination_message = "Sent to destination"
            job.destination_path = result.get("destination_path") or job.destination_path
            job.completed_at = job.completed_at or now()
            job.updated_at = now()
            job.error_message = None

            self.job_repository.update_destination_state(job)

            self._emit_notification_event(
                job,
                event_type="destination.sent",
                severity="info",
                title="Destination sent",
                message="Job was sent to destination.",
            )

            if previous_status != "completed":
                self._emit_notification_event(
                    job,
                    event_type="job.completed",
                    severity="info",
                    title="Job completed",
                    message="Job completed successfully.",
                )

            return job

        except Exception as exc:
            job.destination_status = "failed"
            job.destination_message = str(exc)
            job.error_message = str(exc)
            job.updated_at = now()
            self.job_repository.update_destination_state(job)

            self._emit_notification_event(
                job,
                event_type="destination.failed",
                severity="error",
                title="Destination failed",
                message=str(exc),
                payload={"error": str(exc)},
            )

            raise

    def resend_to_destination(
        self,
        context: UserContext,
        job_id: str,
        destination_name: str | None = None,
        *,
        destination_config_id: str | None = None,
    ) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        if job.status not in {"ready", "partially_ready", "completed"}:
            self._ensure_action_allowed(job, "resend")

        output_links = json.loads(job.output_links_json or "[]")

        if not isinstance(output_links, list):
            raise ValueError("Invalid output links")

        if self._links_expired_or_invalid(output_links):
            output_links = self._rebuild_links(context, job)
            job.output_links_json = json.dumps(output_links)
            job.unrestricted_at = now()
            self.job_repository.update_unrestrict_state(job)

        if not output_links:
            raise ValueError("No output links available")

        return self.send_to_destination(
            context=context,
            job_id=job_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
        )

    def cancel_local_download(self, context: UserContext, job_id: str) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        if job.destination_name != "local":
            raise ValueError("Only local destination downloads can be cancelled")

        current_status = str(job.destination_status or "").strip().lower()

        if current_status not in {"queued", "sending", "downloading"}:
            raise ValueError("Local download is not running or queued")

        job.destination_status = "cancel_requested"
        job.destination_message = "Local download cancellation requested"
        job.send_to_destination = False
        job.sent_to_destination = False
        job.destination_progress = 0
        job.updated_at = now()

        self.job_repository.update_destination_state(job)

        self._emit_notification_event(
            job,
            event_type="destination.cancelled",
            severity="warning",
            title="Destination cancelled",
            message="Local destination download cancellation requested.",
        )

        return job

    def restart_job(self, context: UserContext, job_id: str) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        self._ensure_action_allowed(job, "restart")
        self._ensure_restart_cooldown_elapsed(job)

        job.status = "created"

        job.provider_resource_id = None
        job.provider_status = None
        job.provider_payload_json = None

        job.output_mode = None
        job.output_links_json = None
        job.unrestricted_at = None

        job.error_message = None

        job.started_at = None
        job.completed_at = None
        job.cancelled_at = None

        job.sent_to_destination = False
        job.sent_to_destination_at = None
        job.destination_status = "pending" if job.send_to_destination else None
        job.destination_message = None
        job.destination_message_key = None
        job.destination_message_params = None
        job.destination_last_attempt = None
        job.destination_path = None

        job.updated_at = now()

        self.job_repository.update_full_reset(job)

        return self.start_job(context, job.id)

    def _get_restart_cooldown_seconds(self, job: Job) -> int:
        return get_restart_cooldown_seconds(self.app_settings_service, job)

    def _ensure_restart_cooldown_elapsed(self, job: Job) -> None:
        return ensure_restart_cooldown_elapsed(self.app_settings_service, job)

    def _delete_provider_resources_best_effort(
        self,
        context: UserContext,
        job: Job,
    ) -> None:
        return delete_provider_resources_best_effort(self.provider_factory, context, job)

    def _is_unknown_resource_error(exc: Exception) -> bool:
        return is_unknown_resource_error(exc)

    def cancel_job(self, context: UserContext, job_id: str) -> Job | None:
        job = self.get_job(context, job_id)

        if job is None:
            return None

        self._ensure_action_allowed(job, "cancel")

        try:
            self._delete_provider_resources_best_effort(context, job)
        except Exception as exc:
            job.error_message = str(exc)
            job.updated_at = now()
            self.job_repository.update_status_state(job)
            raise

        timestamp = now()

        job.status = "cancelled"
        job.error_message = None
        job.updated_at = timestamp
        job.completed_at = timestamp
        job.cancelled_at = timestamp

        job.provider_resource_id = None
        job.provider_status = None
        job.provider_payload_json = None

        job.output_mode = None
        job.output_links_json = None
        job.unrestricted_at = None

        job.sent_to_destination = False
        job.sent_to_destination_at = None
        job.destination_status = "pending" if job.send_to_destination else None
        job.destination_message = None
        job.destination_message_key = None
        job.destination_message_params = None
        job.destination_last_attempt = None
        job.destination_path = None

        self.job_repository.update_full_reset(job)

        self._emit_notification_event(
            job,
            event_type="job.cancelled",
            severity="warning",
            title="Job cancelled",
            message="Job was cancelled.",
        )

        return job

    def delete_job(self, context: UserContext, job_id: str) -> bool:
        job = self.get_job(context, job_id)

        if job is None:
            return False

        try:
            self._delete_provider_resources_best_effort(context, job)
        except Exception:
            pass

        self.job_repository.delete(context.user_id, job_id)
        return True

    def _attach_job_metadata_to_output_links(self, job: Job, output_links: list[dict]) -> None:
        payload = json.loads(job.provider_payload_json or "{}")
        files = payload.get("files") or []

        job_filename = (
            payload.get("filename")
            or payload.get("name")
            or job.provider_resource_id
            or "job"
        )

        for index, item in enumerate(output_links):
            item["job_id"] = job.id
            item["job_filename"] = job_filename

            if index < len(files) and isinstance(files[index], dict):
                item["relative_path"] = (
                    files[index].get("path")
                    or files[index].get("filename")
                    or item.get("filename")
                )
            else:
                item["relative_path"] = (
                    item.get("relative_path")
                    or item.get("path")
                    or item.get("filename")
                )

    def _links_expired_or_invalid(self, output_links: list[dict]) -> bool:
        return links_expired_or_invalid(output_links)

    def _rebuild_links(self, context: UserContext, job: Job) -> list[dict]:
        try:
            return self._build_output_links(context, job)
        except Exception as exc:
            self._emit_provider_failed(job, exc)
            raise

