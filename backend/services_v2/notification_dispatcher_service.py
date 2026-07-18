
from __future__ import annotations
import logging
from datetime import datetime, timedelta
from backend.utils.time import utc_now_iso
from backend.services_v2.notification_dispatcher_support.config import load_config_json
from backend.services_v2.notification_dispatcher_support.gotify import send_gotify
from backend.services_v2.notification_dispatcher_support.webhook import send_webhook
from backend.services_v2.notification_dispatcher_support.email import send_email
from backend.services_v2.notification_dispatcher_support.event_dispatch import dispatch_event, mark_event_failure
from backend.services_v2.notification_dispatcher_support.runner import run_once_for_user, run_once_all_users
from typing import Any

now = utc_now_iso
logger = logging.getLogger(__name__)


class NotificationDispatcherService:
    def __init__(
        self,
        notification_config_repository,
        notification_event_repository,
        notification_rule_repository,
        notification_service,
        crypto_service=None,
        smtp_service=None,
        user_repository=None,
        email_template_service=None,
        app_settings_service=None,
        job_repository=None,
        max_attempts: int = 3,
        max_age_hours: int = 24,
    ) -> None:
        self.notification_config_repository = notification_config_repository
        self.notification_event_repository = notification_event_repository
        self.notification_rule_repository = notification_rule_repository
        self.notification_service = notification_service
        self.crypto_service = crypto_service
        self.smtp_service = smtp_service
        self.user_repository = user_repository
        self.email_template_service = email_template_service
        self.app_settings_service = app_settings_service
        self.job_repository = job_repository
        self.max_attempts = max_attempts
        self.max_age_hours = max_age_hours

        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self.last_result: dict[str, Any] | None = None

    def get_status(self, user_id: str | None = None) -> dict:
        return {
            "enabled": True,
            "last_run_at": self.last_run_at,
            "last_error": self.last_error,
            "last_result": self.last_result,
            "message": "Notification dispatcher active",
        }

    def _effective_max_age_hours(self) -> int:
        if self.app_settings_service is not None:
            policy = self.app_settings_service.get_notification_event_policy()
            return int(policy["max_age_hours"])
        return self.max_age_hours

    def cleanup_stale_events_on_startup(self) -> int:
        updated_at = now()
        current = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        max_age_hours = self._effective_max_age_hours()
        cutoff = (current - timedelta(hours=max_age_hours)).isoformat()
        stale_processing_before = (current - timedelta(minutes=10)).isoformat()
        expired = self.notification_event_repository.expire_stale(
            cutoff,
            updated_at,
            stale_processing_before,
        )
        if expired:
            logger.info(
                "Expired %s stale notification events during startup cleanup",
                expired,
            )
        return expired

    def run_once_for_user(self, user_id: str, limit: int = 25) -> dict:
        return run_once_for_user(
            user_id,
            limit,
            self.notification_event_repository,
            self._dispatch_event,
            self._mark_event_failure,
            now,
            self._effective_max_age_hours(),
            on_state_update=self._update_run_state,
        )

    def _dispatch_event(self, user_id: str, event) -> str:
        return dispatch_event(
            user_id,
            event,
            self.notification_event_repository,
            self.notification_config_repository,
            self._send_skeleton,
            now,
        )

    def _send_skeleton(self, config, event) -> None:
        channel = str(getattr(config, "channel", "") or "").strip().lower()

        if channel == "gotify":
            self._send_gotify(config, event)
            return

        if channel == "webhook":
            self._send_webhook(config, event)
            return

        if channel == "email":
            self._send_email(config, event)
            return

        raise ValueError(f"Unsupported notification channel: {channel}")

    def _mark_event_failure(self, event, exc: Exception) -> None:
        mark_event_failure(
            event,
            exc,
            self.notification_event_repository,
            self.max_attempts,
        )

    def _load_config_json(self, config) -> dict:
        return load_config_json(config, crypto_service=self.crypto_service)

    def _send_gotify(self, config, event) -> None:
        cfg = self._load_config_json(config)
        send_gotify(cfg, event)

    def _send_email(self, config, event) -> None:
        cfg = self._load_config_json(config)
        send_email(
            cfg,
            config,
            event,
            smtp_service=self.smtp_service,
            user_repository=self.user_repository,
            email_template_service=self.email_template_service,
            app_settings_service=self.app_settings_service,
            job_repository=self.job_repository,
        )

    def _send_webhook(self, config, event) -> None:
        cfg = self._load_config_json(config)
        send_webhook(cfg, config, event)

    def run_once_all_users(self, limit: int = 25) -> dict:
        return run_once_all_users(
            limit,
            self.user_repository,
            self.run_once_for_user,
            now,
            on_state_update=self._update_run_state,
        )

    def _update_run_state(self, finished_at: str, last_error: str | None, result: dict) -> None:
        self.last_run_at = finished_at
        self.last_error = last_error
        self.last_result = result
