
from __future__ import annotations
from datetime import UTC, datetime, timedelta
from backend.utils.time import utc_now_iso
from backend.services_v2.notification_dispatcher_support.config import load_config_json
from backend.services_v2.notification_dispatcher_support.gotify import send_gotify
from backend.services_v2.notification_dispatcher_support.webhook import send_webhook
from backend.services_v2.notification_dispatcher_support.email import send_email
from typing import Any
import json

now = utc_now_iso


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
    def run_once_for_user(self, user_id: str, limit: int = 25) -> dict:
        started_at = now()

        result = {
            "started_at": started_at,
            "finished_at": None,
            "user_id": user_id,
            "limit": limit,
            "processed": 0,
            "sent": 0,
            "retrying": 0,
            "failed": 0,
            "skipped": 0,
            "errors": [],
        }

        try:
            events = self.notification_event_repository.list_for_user(
                user_id=user_id,
                limit=limit,
            )

            candidates = [
                event
                for event in events
                if str(getattr(event, "status", "") or "").lower() in {"pending", "retrying"}
            ]

            for event in candidates[:limit]:
                result["processed"] += 1

                try:
                    outcome = self._dispatch_event(user_id, event)

                    if outcome == "sent":
                        result["sent"] += 1
                    elif outcome == "skipped":
                        result["skipped"] += 1
                    else:
                        result["skipped"] += 1

                except Exception as exc:
                    self._mark_event_failure(event, exc)

                    refreshed = self.notification_event_repository.get_by_id(user_id, event.id)
                    status = str(getattr(refreshed, "status", "") or "").lower()

                    if status == "failed":
                        result["failed"] += 1
                    else:
                        result["retrying"] += 1

                    result["errors"].append({
                        "event_id": event.id,
                        "error": str(exc),
                    })

            result["finished_at"] = now()
            self.last_run_at = result["finished_at"]
            self.last_error = None if not result["errors"] else result["errors"][-1]["error"]
            self.last_result = result

            return result

        except Exception as exc:
            result["finished_at"] = now()
            result["errors"].append({
                "error": str(exc),
            })

            self.last_run_at = result["finished_at"]
            self.last_error = str(exc)
            self.last_result = result

            raise

    def _dispatch_event(self, user_id: str, event) -> str:
        triggered_config_ids = self._get_triggered_config_ids(event)

        if not triggered_config_ids:
            # Un event ignored ne devrait normalement pas être pending.
            self.notification_event_repository.mark_sent(event.id, now())
            return "skipped"

        for config_id in triggered_config_ids:
            config = self.notification_config_repository.get_by_id(user_id, config_id)

            if not config:
                raise ValueError(f"Notification config not found: {config_id}")

            if not getattr(config, "is_enabled", False):
                continue

            self._send_skeleton(config, event)

        self.notification_event_repository.mark_sent(event.id, now())
        return "sent"

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

    def _event_max_attempts(self, event) -> int:
        try:
            value = int(getattr(event, "max_attempts", None) or self.max_attempts)
        except Exception:
            value = self.max_attempts

        return max(1, value)
        
    def _mark_event_failure(self, event, exc: Exception) -> None:
        attempts = int(getattr(event, "attempts", 0) or 0) + 1
        event_max_attempts = self._event_max_attempts(event)

        if attempts >= event_max_attempts:
            self.notification_event_repository.mark_failed(
                event.id,
                str(exc),
            )
            return

        next_retry_at = (
            datetime.now(UTC) + timedelta(minutes=min(30, attempts * 5))
        ).isoformat()

        self.notification_event_repository.mark_retrying(
            event.id,
            str(exc),
            next_retry_at,
        )
    def _get_triggered_config_ids(self, event) -> list[str]:
        value = getattr(event, "triggered_by_config_ids", None)

        if isinstance(value, list):
            raw_ids = value
        else:
            raw = getattr(event, "triggered_by_config_ids_json", None)

            if not raw:
                return []

            try:
                decoded = json.loads(raw)
            except Exception:
                return []

            if not isinstance(decoded, list):
                return []

            raw_ids = decoded

        seen = set()
        result = []

        for item in raw_ids:
            config_id = str(item).strip()
            if not config_id or config_id in seen:
                continue

            seen.add(config_id)
            result.append(config_id)

        return result

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
        started_at = now()

        result = {
            "started_at": started_at,
            "finished_at": None,
            "limit": limit,
            "users_processed": 0,
            "processed": 0,
            "sent": 0,
            "retrying": 0,
            "failed": 0,
            "skipped": 0,
            "errors": [],
            "per_user": [],
        }

        try:
            if not self.user_repository:
                raise RuntimeError("User repository is not configured")

            if hasattr(self.user_repository, "list_all"):
                users = self.user_repository.list_all()
            elif hasattr(self.user_repository, "list_users"):
                users = self.user_repository.list_users()
            elif hasattr(self.user_repository, "list"):
                users = self.user_repository.list()
            else:
                raise RuntimeError("User repository has no list method")

            for user in users:
                user_id = str(getattr(user, "id", "") or "").strip()
                is_active = bool(getattr(user, "is_active", False))

                if not user_id or not is_active:
                    continue

                user_result = self.run_once_for_user(
                    user_id=user_id,
                    limit=limit,
                )

                result["users_processed"] += 1
                result["processed"] += int(user_result.get("processed") or 0)
                result["sent"] += int(user_result.get("sent") or 0)
                result["retrying"] += int(user_result.get("retrying") or 0)
                result["failed"] += int(user_result.get("failed") or 0)
                result["skipped"] += int(user_result.get("skipped") or 0)

                if user_result.get("errors"):
                    result["errors"].extend(user_result["errors"])

                result["per_user"].append(user_result)

            result["finished_at"] = now()
            self.last_run_at = result["finished_at"]
            self.last_error = None if not result["errors"] else str(result["errors"][-1].get("error"))
            self.last_result = result

            return result

        except Exception as exc:
            result["finished_at"] = now()
            result["errors"].append({"error": str(exc)})

            self.last_run_at = result["finished_at"]
            self.last_error = str(exc)
            self.last_result = result

            raise