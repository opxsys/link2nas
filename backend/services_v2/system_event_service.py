from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any


class SystemEventService:
    """
    Creates system/app notification events for active super admins.

    Deduplication is configured through:
      app_settings key: system_events.dedup
      shape: {"enabled": true, "dedup_minutes": 60}

    This service does not send notifications directly.
    It creates notification events through NotificationService.
    The existing notification dispatcher/rules decide whether/how to send them.
    """

    def __init__(
        self,
        *,
        app_settings_service,
        notification_service,
        notification_event_repository,
        user_repository,
    ) -> None:
        self.app_settings_service = app_settings_service
        self.notification_service = notification_service
        self.notification_event_repository = notification_event_repository
        self.user_repository = user_repository

    def now(self) -> datetime:
        return datetime.now(UTC)

    def now_iso(self) -> str:
        return self.now().isoformat()

    def create_for_super_admins(
        self,
        *,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        component: str,
        fingerprint: str,
        details: dict[str, Any] | None = None,
    ) -> dict:
        settings = self.app_settings_service.get_system_events_dedup()
        enabled = bool(settings.get("enabled", True))
        dedup_minutes = int(settings.get("dedup_minutes") or 60)

        result = {
            "enabled": enabled,
            "event_type": event_type,
            "severity": severity,
            "component": component,
            "fingerprint": fingerprint,
            "dedup_minutes": dedup_minutes,
            "created": 0,
            "skipped": 0,
            "errors": [],
            "events": [],
        }

        if not enabled:
            result["skipped_reason"] = "system events disabled"
            return result

        for user in self._list_active_super_admins():
            user_id = str(getattr(user, "id", "") or "").strip()
            if not user_id:
                continue

            try:
                if self._is_duplicate(
                    user_id=user_id,
                    event_type=event_type,
                    severity=severity,
                    fingerprint=fingerprint,
                    dedup_minutes=dedup_minutes,
                ):
                    result["skipped"] += 1
                    continue
                event = self.notification_service.create_event(
                    user_id=user_id,
                    type=event_type,
                    severity=severity,
                    title=title,
                    message=message,
                    job_id=None,
                    payload={
                        "source": "system",
                        "component": component,
                        "fingerprint": fingerprint,
                        "details": details or {},
                        "created_by": "system_event_service",
                    },
                    scope="system",
                )

                result["created"] += 1
                result["events"].append({
                    "user_id": user_id,
                    "event_id": event.get("id"),
                    "status": event.get("status"),
                })

            except Exception as exc:
                result["errors"].append({
                    "user_id": user_id,
                    "error": str(exc),
                })

        return result

    def _list_active_super_admins(self) -> list[Any]:
        if hasattr(self.user_repository, "list_all"):
            users = self.user_repository.list_all()
        elif hasattr(self.user_repository, "list_users"):
            users = self.user_repository.list_users()
        elif hasattr(self.user_repository, "list"):
            users = self.user_repository.list()
        else:
            raise RuntimeError("User repository has no list method")

        result = []

        for user in users:
            is_active = bool(getattr(user, "is_active", False))
            role = str(getattr(user, "role", "") or "").strip().lower()

            if is_active and role == "super_admin":
                result.append(user)

        return result

    def _is_duplicate(
        self,
        *,
        user_id: str,
        event_type: str,
        severity: str,
        fingerprint: str,
        dedup_minutes: int,
    ) -> bool:
        if dedup_minutes <= 0:
            return False

        cutoff = self.now() - timedelta(minutes=dedup_minutes)

        # list_for_user is ordered newest first in current repositories.
        # Limit 200 is enough for anti-spam without adding a repository method yet.
        events = self.notification_event_repository.list_for_user(
            user_id=user_id,
            limit=200,
        )

        for event in events:
            if str(getattr(event, "type", "") or "") != event_type:
                continue

            if str(getattr(event, "severity", "") or "").lower() != str(severity).lower():
                continue

            created_at = self._parse_datetime(getattr(event, "created_at", None))
            if created_at is None or created_at < cutoff:
                continue

            payload = self._load_payload(getattr(event, "payload_json", None))
            existing_fingerprint = str(payload.get("fingerprint") or "").strip()

            if existing_fingerprint == fingerprint:
                return True

        return False

    def _load_payload(self, raw: Any) -> dict:
        if isinstance(raw, dict):
            return raw

        try:
            decoded = json.loads(str(raw or "{}"))
        except Exception:
            return {}

        return decoded if isinstance(decoded, dict) else {}

    def _parse_datetime(self, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            dt = value
        else:
            raw = str(value or "").strip()
            if not raw:
                return None

            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except Exception:
                return None

        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)

        return dt.astimezone(UTC)
