import json
import logging

from backend.utils.time import utc_now_iso

from flask import current_app

from backend.models.job import Job
from backend.services_v2.user_context import UserContext
from backend.services_v2.job_support.provider_failure import (
    classify_provider_error_message,
    is_persistable_provider_error,
)

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
from backend.services_v2.job_support.output_links import attach_job_metadata_to_output_links
from backend.services_v2.job_support.local_download_queue import enqueue_local_download
from backend.services_v2.job_support.unrestrict_links import build_output_links
from backend.services_v2.job_support.file_selection import resolve_files_to_select
from backend.services_v2.job_support.listing import filter_jobs_by_status
from backend.services_v2.job_support.actions import (
    get_allowed_actions,
    ensure_action_allowed,
)
from backend.services_v2.job_support.provider_start import set_started_provider_job
from backend.services_v2.job_support.unrestrict_file import unrestrict_file_impl
from backend.services_v2.job_support.unrestrict_job import unrestrict_job_impl
from backend.services_v2.job_support.refresh import refresh_job_impl
from backend.services_v2.job_support.select_files import select_files_impl
from backend.services_v2.job_support.local_download_cancel import cancel_local_download_impl
from backend.services_v2.job_support.restart import restart_job_impl
from backend.services_v2.job_support.cancel import cancel_job_impl
from backend.services_v2.job_support.delete import delete_job_impl
from backend.services_v2.job_support.resend_destination import resend_to_destination_impl
from backend.services_v2.job_support.local_destination_send import send_to_local_destination_impl
from backend.services_v2.job_support.non_local_destination_send import send_to_non_local_destination_impl
from backend.services_v2.job_support.destination_prepare import prepare_destination_send
from backend.services_v2.job_support.destination_error import apply_destination_failure
from backend.services_v2.job_support.start import start_job_impl

now = utc_now_iso

logger = logging.getLogger(__name__)


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
        return get_allowed_actions(job)

    def _ensure_action_allowed(self, job: Job, action: str) -> None:
        return ensure_action_allowed(job, action)

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

    def _mark_job_failed_if_provider_error(self, job: Job, exc: Exception) -> None:
        """Persist job as failed if exc is an expected provider content/API error.

        Uses classify_provider_error_message (no logging) so the single WARNING
        log entry happens later when the route formats the HTTP response.
        """
        if not is_persistable_provider_error(exc):
            return
        safe_msg = classify_provider_error_message(exc)
        job.status = "failed"
        job.error_message = safe_msg
        job.updated_at = now()
        try:
            self.job_repository.update_status_state(job)
        except Exception:
            logger.exception("Failed to persist failed state for job %s", job.id)

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
        return filter_jobs_by_status(jobs, status)

    def start_job(self, context: UserContext, job_id: str) -> Job | None:
        return start_job_impl(self, context, job_id)

    def _set_started_provider_job(self, job: Job, result: dict) -> Job:
        return set_started_provider_job(
            self.job_repository,
            self.notification_service,
            job,
            result,
        )

    def _resolve_files_to_select(self, provider_payload: dict) -> str:
        return resolve_files_to_select(provider_payload)

    def refresh_job(self, context: UserContext, job_id: str) -> Job | None:
        return refresh_job_impl(self, context, job_id)

    def select_files(
        self,
        context: UserContext,
        job_id: str,
        files: str,
    ) -> Job | None:
        return select_files_impl(self, context, job_id, files)

    def unrestrict_job(self, context: UserContext, job_id: str) -> Job | None:
        return unrestrict_job_impl(self, context, job_id)

    def unrestrict_file(self, context: UserContext, job_id: str, file_id: int) -> Job | None:
        return unrestrict_file_impl(self, context, job_id, file_id)

    def _build_output_links(self, context: UserContext, job: Job) -> list[dict]:
        return build_output_links(self.provider_factory, context, job)

    def _enqueue_local_download(
        self,
        context: UserContext,
        job: Job,
        destination_config_id: str | None,
    ) -> None:
        return enqueue_local_download(
            current_app.config["SETTINGS"],
            context,
            job,
            destination_config_id,
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

        resolved, output_links = prepare_destination_send(
            self,
            context,
            job,
            destination_name,
            destination_config_id,
        )

        try:
            self._attach_job_metadata_to_output_links(job, output_links)
            job.output_links_json = json.dumps(output_links)

            if resolved.name == "local":
                return send_to_local_destination_impl(
                    self,
                    context,
                    job,
                    resolved,
                    output_links,
                )

            return send_to_non_local_destination_impl(
                self,
                job,
                resolved,
                output_links,
                previous_status,
            )

        except Exception as exc:
            apply_destination_failure(job, exc)
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
        return resend_to_destination_impl(
            self,
            context,
            job_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
        )

    def cancel_local_download(self, context: UserContext, job_id: str) -> Job | None:
        return cancel_local_download_impl(self, context, job_id)

    def restart_job(self, context: UserContext, job_id: str) -> Job | None:
        return restart_job_impl(self, context, job_id)

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
        return cancel_job_impl(self, context, job_id)

    def delete_job(self, context: UserContext, job_id: str) -> bool:
        return delete_job_impl(self, context, job_id)

    def _attach_job_metadata_to_output_links(self, job: Job, output_links: list[dict]) -> None:
        return attach_job_metadata_to_output_links(job, output_links)

    def _links_expired_or_invalid(self, output_links: list[dict]) -> bool:
        return links_expired_or_invalid(output_links)

    def _rebuild_links(self, context: UserContext, job: Job) -> list[dict]:
        try:
            return self._build_output_links(context, job)
        except Exception as exc:
            self._emit_provider_failed(job, exc)
            raise

