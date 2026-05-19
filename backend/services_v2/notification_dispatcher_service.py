
from __future__ import annotations
from backend.services_v2.smtp_service import SmtpServiceError
from datetime import UTC, datetime, timedelta
from backend.utils.time import utc_now_iso
from typing import Any
import json
import os
import requests

now = utc_now_iso


def _build_user_summary(event_type: str, title: str, message: str, lang: str | None) -> str:
    is_fr = not str(lang or "").lower().startswith("en")

    fr = {
        "job.completed": "Le job est terminé.",
        "job.failed": "Le job a échoué.",
        "job.links_ready": "Les liens directs du job sont disponibles.",
        "destination.sent": "Le job a été envoyé vers la destination.",
        "destination.failed": "L'envoi vers la destination a échoué.",
        "provider.failed": "Le provider a signalé une erreur.",
        "provider.ready": "Le provider a terminé la préparation.",
    }
    en = {
        "job.completed": "The job is complete.",
        "job.failed": "The job failed.",
        "job.links_ready": "Direct links are available for this job.",
        "destination.sent": "The job was sent to the destination.",
        "destination.failed": "Sending the job to the destination failed.",
        "provider.failed": "The provider reported an error.",
        "provider.ready": "The provider finished preparing the job.",
    }

    mapping = fr if is_fr else en
    fallback = "Notification Link2NAS" if is_fr else "Link2NAS notification"
    return mapping.get(str(event_type or "").strip()) or title or message or fallback


def _resolve_job_name(provider_payload: dict, job_id: str | None, lang: str | None) -> str:
    filename = str(provider_payload.get("filename") or "").strip()
    if filename:
        return filename

    files = provider_payload.get("files")
    if isinstance(files, list):
        paths = [str(f.get("path") or "").strip() for f in files if isinstance(f, dict)]
        paths = [p for p in paths if p]
        if paths:
            if len(paths) == 1:
                return os.path.basename(paths[0]) or paths[0]
            try:
                common = os.path.commonpath(paths)
            except (ValueError, TypeError):
                common = ""
            if common and common not in (".", ""):
                name = os.path.basename(common)
                return name if name else common
            return os.path.basename(paths[0]) or paths[0]

    if job_id:
        return f"Job {str(job_id)[:8]}"

    is_fr = not str(lang or "").lower().startswith("en")
    return "Système" if is_fr else "System"


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
        raw = getattr(config, "config_json", None)

        if not raw:
            return {}

        value = str(raw)

        if value.startswith("enc::"):
            if self.crypto_service is None:
                raise RuntimeError("Crypto service is not configured")

            value = self.crypto_service.decrypt(value)

        try:
            decoded = json.loads(value)
        except Exception as exc:
            raise ValueError("Invalid notification config JSON") from exc

        if not isinstance(decoded, dict):
            raise ValueError("Notification config JSON must be an object")

        return decoded

    def _send_gotify(self, config, event) -> None:
        cfg = self._load_config_json(config)

        server_url = str(cfg.get("server_url") or "").strip().rstrip("/")
        token = str(cfg.get("token") or "").strip()

        if not server_url:
            raise ValueError("Gotify server_url is required")

        if not token:
            raise ValueError("Gotify token is required")

        title = str(getattr(event, "title", "") or "Link2NAS notification").strip()
        message = str(getattr(event, "message", "") or "").strip()
        severity = str(getattr(event, "severity", "") or "info").strip().lower()
        event_type = str(getattr(event, "type", "") or "").strip()

        priority = self._gotify_priority_for_severity(severity)

        full_message = message

        if event_type:
            full_message = f"{message}\n\nType: {event_type}".strip()

        job_id = getattr(event, "job_id", None)
        if job_id:
            full_message = f"{full_message}\nJob: {job_id}".strip()

        url = f"{server_url}/message"

        response = requests.post(
            url,
            params={"token": token},
            json={
                "title": title,
                "message": full_message,
                "priority": priority,
            },
            timeout=8,
        )

        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(
                f"Gotify HTTP {response.status_code}: {response.text[:300]}"
            )

    def _send_email(self, config, event) -> None:
        if not self.smtp_service:
            raise RuntimeError("SMTP service is not configured")

        cfg = self._load_config_json(config)

        to_email = str(cfg.get("to_email") or "").strip()
        user = None

        if not to_email:
            if not self.user_repository:
                raise RuntimeError("User repository is not configured")

            user_id = str(getattr(event, "user_id", "") or "").strip()
            user = self.user_repository.get_by_id(user_id) if user_id else None
            to_email = str(getattr(user, "email", None) or "").strip() if user else ""

        if not to_email:
            raise ValueError("Email target is required")

        title = str(getattr(event, "title", None) or "Link2NAS notification").strip()
        message = str(getattr(event, "message", None) or "").strip()
        event_type = str(getattr(event, "type", None) or "").strip()
        severity = str(getattr(event, "severity", None) or "").strip()
        job_id = str(getattr(event, "job_id", None) or "").strip()
        event_id = str(getattr(event, "id", None) or "").strip()
        config_name = str(getattr(config, "name", None) or "").strip()
        created_at = str(getattr(event, "created_at", None) or "").strip()

        if self.email_template_service:
            app_name = "Link2NAS"
            if self.app_settings_service:
                try:
                    app_name = self.app_settings_service.get_effective_app_name() or "Link2NAS"
                except Exception:
                    pass

            if user is None and self.user_repository:
                try:
                    uid = str(getattr(event, "user_id", "") or "").strip()
                    if uid:
                        user = self.user_repository.get_by_id(uid)
                except Exception:
                    pass

            lang = getattr(user, "preferred_language", None) if user else None

            provider_payload: dict = {}
            if job_id and self.job_repository:
                try:
                    uid = str(getattr(event, "user_id", "") or "").strip()
                    job = self.job_repository.get_by_id(uid, job_id) if uid else None
                    raw = str(getattr(job, "provider_payload_json", None) or "").strip() if job else ""
                    provider_payload = json.loads(raw) if raw else {}
                except Exception:
                    provider_payload = {}

            job_name = _resolve_job_name(provider_payload, job_id or None, lang)
            user_summary = _build_user_summary(event_type, title, message, lang)

            subject, body = self.email_template_service.render(
                "notification_event",
                lang,
                app_name=app_name,
                title=title,
                message=message,
                event_type=event_type,
                severity=severity,
                job_id=job_id,
                job_name=job_name,
                event_id=event_id,
                config_name=config_name,
                created_at=created_at,
                user_summary=user_summary,
            )
        else:
            job_name = _resolve_job_name({}, job_id or None, None)
            body_parts = [
                message,
                "",
                f"Job: {job_name}" if job_name else "",
                f"Type: {event_type}" if event_type else "",
                f"Severity: {severity}" if severity else "",
                f"Job ID: {job_id}" if job_id else "",
                f"Event ID: {event_id}",
                f"Config: {config_name}",
            ]
            body = "\n".join(part for part in body_parts if part is not None).strip()
            subject = f"Link2NAS - {title}"

        try:
            self.smtp_service.send_email(
                to_email=to_email,
                subject=subject,
                body=body,
            )
        except SmtpServiceError as exc:
            raise RuntimeError(str(exc)) from exc

    def _send_webhook(self, config, event) -> None:
        cfg = self._load_config_json(config)

        url = str(cfg.get("url") or "").strip()
        method = str(cfg.get("method") or "POST").strip().upper()
        headers = cfg.get("headers") or {}

        if not url:
            raise ValueError("Webhook url is required")

        if method not in {"POST", "PUT"}:
            raise ValueError("Webhook method must be POST or PUT")

        if not isinstance(headers, dict):
            raise ValueError("Webhook headers must be an object")

        payload = self._build_webhook_payload(config, event)

        response = requests.request(
            method,
            url,
            headers=headers,
            json=payload,
            timeout=8,
        )

        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(
                f"Webhook HTTP {response.status_code}: {response.text[:300]}"
            )

    def _build_webhook_payload(self, config, event) -> dict:
        raw_payload = getattr(event, "payload", None)

        if isinstance(raw_payload, dict):
            event_payload = raw_payload
        else:
            raw_payload_json = getattr(event, "payload_json", None) or "{}"

            try:
                decoded = json.loads(raw_payload_json)
            except Exception:
                decoded = {}

            event_payload = decoded if isinstance(decoded, dict) else {}

        return {
            "app": "link2nas",
            "config_id": getattr(config, "id", None),
            "config_name": getattr(config, "name", None),
            "event_id": getattr(event, "id", None),
            "user_id": getattr(event, "user_id", None),
            "job_id": getattr(event, "job_id", None),
            "type": getattr(event, "type", None),
            "severity": getattr(event, "severity", None),
            "title": getattr(event, "title", None),
            "message": getattr(event, "message", None),
            "status": getattr(event, "status", None),
            "attempts": getattr(event, "attempts", None),
            "created_at": getattr(event, "created_at", None),
            "updated_at": getattr(event, "updated_at", None),
            "payload": event_payload,
        }

    def _gotify_priority_for_severity(self, severity: str) -> int:
        value = str(severity or "").strip().lower()

        if value == "critical":
            return 10

        if value == "error":
            return 8

        if value == "warning":
            return 5

        return 2

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