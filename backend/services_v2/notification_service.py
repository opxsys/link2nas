import json
import requests
import uuid
from backend.utils.time import utc_now_iso

from backend.models.notification_config import NotificationConfig
from backend.models.notification_event import NotificationEvent
from backend.models.notification_rule import NotificationRule
from backend.services_v2.smtp_service import SmtpServiceError
from backend.services_v2.notification_support.validation import (
    NotificationValidationError,
    require_text,
    validate_channel,
    validate_severity,
    validate_scope,
    validate_event_types,
    validate_rate_limit,
    severity_rank,
)
from backend.services_v2.notification_support.serialization import (
    config_to_public_dict,
    rule_to_public_dict,
    event_to_public_dict,
    safe_config,
)
from backend.services_v2.notification_support.config_codec import encode_config, decode_config
from backend.services_v2.notification_support.config_serialization import serialize_config


class NotificationNotFoundError(Exception):
    pass


now = utc_now_iso

class NotificationService:
    def __init__(
        self,
        notification_config_repository,
        notification_rule_repository,
        notification_event_repository,
        crypto_service=None,
        smtp_service=None,
        user_repository=None,
        email_template_service=None,
        app_settings_service=None,
    ) -> None:
        self.notification_config_repository = notification_config_repository
        self.notification_rule_repository = notification_rule_repository
        self.notification_event_repository = notification_event_repository
        self.crypto_service = crypto_service
        self.smtp_service = smtp_service
        self.user_repository = user_repository
        self.email_template_service = email_template_service
        self.app_settings_service = app_settings_service

    # -------------------------------------------------------------------------
    # Configs = endpoints / channels
    # -------------------------------------------------------------------------

    def list_configs(self, user_id: str) -> list[dict]:
        configs = self.notification_config_repository.list_for_user(user_id)
        return [self._config_to_public_dict(config) for config in configs]

    def get_config(self, user_id: str, config_id: str) -> dict:
        config = self.notification_config_repository.get_by_id(user_id, config_id)

        if not config:
            raise NotificationNotFoundError("Notification config not found")

        return self._config_to_public_dict(config)

    def create_config(self, user_id: str, payload: dict) -> dict:
        timestamp = now()

        name = self._require_text(payload.get("name"), "name")
        channel = self._validate_channel(payload.get("channel"))

        if channel == "email" and self.smtp_service and not self.smtp_service.is_email_sending_available():
            raise NotificationValidationError("Email sending is not configured.")

        is_enabled = bool(payload.get("is_enabled", True))
        is_default = bool(payload.get("is_default", False))

        config_payload = payload.get("config") or {}
        config_json = self._serialize_config(channel, config_payload, existing_config=None)

        config = NotificationConfig(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name=name,
            channel=channel,
            is_enabled=is_enabled,
            is_default=is_default,
            config_json=config_json,
            created_at=timestamp,
            updated_at=timestamp,
        )

        saved = self.notification_config_repository.create(config)
        return self._config_to_public_dict(saved)

    def update_config(self, user_id: str, config_id: str, payload: dict) -> dict:
        existing = self.notification_config_repository.get_by_id(user_id, config_id)

        if not existing:
            raise NotificationNotFoundError("Notification config not found")

        timestamp = now()

        name = self._require_text(payload.get("name", existing.name), "name")
        channel = self._validate_channel(payload.get("channel", existing.channel))
        is_enabled = bool(payload.get("is_enabled", existing.is_enabled))
        is_default = bool(payload.get("is_default", existing.is_default))

        config_payload = payload.get("config")
        config_json = self._serialize_config(
            channel,
            config_payload,
            existing_config=existing,
        )

        updated = NotificationConfig(
            id=existing.id,
            user_id=existing.user_id,
            name=name,
            channel=channel,
            is_enabled=is_enabled,
            is_default=is_default,
            config_json=config_json,
            created_at=existing.created_at,
            updated_at=timestamp,
        )

        saved = self.notification_config_repository.update(updated)

        if not is_enabled:
            timestamp_rules = now()
            for rule in self.notification_rule_repository.list_for_user(user_id):
                if rule.config_id == config_id and rule.is_enabled:
                    self.notification_rule_repository.update(NotificationRule(
                        id=rule.id,
                        user_id=rule.user_id,
                        name=rule.name,
                        scope=rule.scope,
                        is_enabled=False,
                        config_id=rule.config_id,
                        severity_min=rule.severity_min,
                        event_types_json=rule.event_types_json,
                        rate_limit_per_hour=rule.rate_limit_per_hour,
                        created_at=rule.created_at,
                        updated_at=timestamp_rules,
                    ))

        return self._config_to_public_dict(saved)

    def delete_config(self, user_id: str, config_id: str) -> bool:
        return self.notification_config_repository.delete(user_id, config_id)
        
    def test_config(self, user_id: str, config_id: str) -> dict:
        config = self.notification_config_repository.get_by_id(user_id, config_id)

        if not config:
            raise NotificationNotFoundError("Notification config not found")

        decoded = self._decode_config(config.config_json)
        channel = self._validate_channel(config.channel)

        if channel == "email":
            to_email = str(decoded.get("to_email") or "").strip()
            user = None

            if self.user_repository:
                user = self.user_repository.get_by_id(user_id)
                if not to_email:
                    to_email = str(getattr(user, "email", None) or "").strip() if user else ""
            elif not to_email:
                raise NotificationValidationError("User repository is not configured")

            if not to_email:
                raise NotificationValidationError("Email target is required")

            if not self.smtp_service:
                raise NotificationValidationError("SMTP service is not configured")

            lang = str(getattr(user, "preferred_language", None) or "fr").lower() if user else "fr"

            app_name = "Link2NAS"
            if self.app_settings_service:
                app_name = self.app_settings_service.get_effective_app_name() or "Link2NAS"

            public_base_url = ""
            if self.app_settings_service:
                public_base_url = self.app_settings_service.get_effective_public_base_url() or ""

            if self.email_template_service:
                subject, body = self.email_template_service.render(
                    "notification_test",
                    lang,
                    app_name=app_name,
                    channel_name=config.name,
                    channel=config.channel,
                    to_email=to_email,
                    config_id=config.id,
                    public_base_url=public_base_url,
                )
            else:
                subject = f"[{app_name}] Test notification"
                if lang == "en":
                    body = f'This is a test email for notification channel "{config.name}".'
                else:
                    body = f'Ceci est un email de test pour le canal de notification « {config.name} ».'

            success_msg = f"Test email sent to {to_email}." if lang == "en" else f"Email de test envoyé à {to_email}."

            try:
                self.smtp_service.send_email(to_email=to_email, subject=subject, body=body)
            except SmtpServiceError as exc:
                raise NotificationValidationError(str(exc)) from exc

            return {
                "ok": True,
                "channel": "email",
                "config_id": config.id,
                "message": success_msg,
            }
        if channel == "gotify":
            server_url = str(decoded.get("server_url") or "").strip().rstrip("/")
            token = str(decoded.get("token") or "").strip()

            if not server_url:
                raise NotificationValidationError("Gotify server_url is required")

            if not token:
                raise NotificationValidationError("Gotify token is required")

            response = requests.post(
                f"{server_url}/message",
                params={"token": token},
                json={
                    "title": "Link2NAS - Test Gotify",
                    "message": (
                        "Ceci est un message de test depuis Link2NAS.\n\n"
                        f"Canal: {config.name}"
                    ),
                    "priority": 5,
                },
                timeout=8,
            )

            if response.status_code < 200 or response.status_code >= 300:
                raise NotificationValidationError(
                    f"Gotify HTTP {response.status_code}: {response.text[:300]}"
                )

            return {
                "ok": True,
                "channel": "gotify",
                "config_id": config.id,
                "message": "Message de test Gotify envoyé.",
            }

        if channel == "webhook":
            url = str(decoded.get("url") or "").strip()
            method = str(decoded.get("method") or "POST").strip().upper()
            headers = decoded.get("headers") or {}

            if not url:
                raise NotificationValidationError("Webhook url is required")

            if method not in {"POST", "PUT"}:
                raise NotificationValidationError("Webhook method must be POST or PUT")

            if not isinstance(headers, dict):
                raise NotificationValidationError("Webhook headers must be an object")

            payload = {
                "app": "link2nas",
                "test": True,
                "channel": "webhook",
                "config_id": config.id,
                "config_name": config.name,
                "type": "notification.test",
                "severity": "info",
                "title": "Link2NAS - Test Webhook",
                "message": "Ceci est un message de test depuis Link2NAS.",
                "created_at": now(),
            }

            response = requests.request(
                method,
                url,
                headers=headers,
                json=payload,
                timeout=8,
            )

            if response.status_code < 200 or response.status_code >= 300:
                raise NotificationValidationError(
                    f"Webhook HTTP {response.status_code}: {response.text[:300]}"
                )

            return {
                "ok": True,
                "channel": "webhook",
                "config_id": config.id,
                "message": "Message de test Webhook envoyé.",
            }

        raise NotificationValidationError("Unsupported notification channel")
    # -------------------------------------------------------------------------
    # Rules = subscriptions
    # -------------------------------------------------------------------------

    def list_rules(self, user_id: str) -> list[dict]:
        rules = self.notification_rule_repository.list_for_user(user_id)
        return [self._rule_to_public_dict(rule) for rule in rules]

    def get_rule(self, user_id: str, rule_id: str) -> dict:
        rule = self.notification_rule_repository.get_by_id(user_id, rule_id)

        if not rule:
            raise NotificationNotFoundError("Notification rule not found")

        return self._rule_to_public_dict(rule)

    def create_rule(self, user_id: str, payload: dict) -> dict:
        timestamp = now()

        name = self._require_text(payload.get("name"), "name")
        scope = self._validate_scope(payload.get("scope", "user"))
        is_enabled = bool(payload.get("is_enabled", True))
        config_id = self._require_text(payload.get("config_id"), "config_id")
        severity_min = self._validate_severity(payload.get("severity_min", "info"))
        event_types = self._validate_event_types(payload.get("event_types", []))
        rate_limit_per_hour = self._validate_rate_limit(payload.get("rate_limit_per_hour", 30))

        config = self.notification_config_repository.get_by_id(user_id, config_id)
        if not config:
            raise NotificationValidationError("Notification config not found")
        if is_enabled and not config.is_enabled:
            raise NotificationValidationError("Notification config is disabled")

        rule = NotificationRule(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name=name,
            scope=scope,
            is_enabled=is_enabled,
            config_id=config_id,
            severity_min=severity_min,
            event_types_json=json.dumps(event_types),
            rate_limit_per_hour=rate_limit_per_hour,
            created_at=timestamp,
            updated_at=timestamp,
        )

        saved = self.notification_rule_repository.create(rule)
        return self._rule_to_public_dict(saved)

    def update_rule(self, user_id: str, rule_id: str, payload: dict) -> dict:
        existing = self.notification_rule_repository.get_by_id(user_id, rule_id)

        if not existing:
            raise NotificationNotFoundError("Notification rule not found")

        timestamp = now()

        name = self._require_text(payload.get("name", existing.name), "name")
        scope = self._validate_scope(payload.get("scope", existing.scope))
        is_enabled = bool(payload.get("is_enabled", existing.is_enabled))
        config_id = self._require_text(payload.get("config_id", existing.config_id), "config_id")
        severity_min = self._validate_severity(payload.get("severity_min", existing.severity_min))
        event_types = self._validate_event_types(
            payload.get("event_types", json.loads(existing.event_types_json or "[]"))
        )
        rate_limit_per_hour = self._validate_rate_limit(
            payload.get("rate_limit_per_hour", existing.rate_limit_per_hour)
        )

        config = self.notification_config_repository.get_by_id(user_id, config_id)
        if not config:
            raise NotificationValidationError("Notification config not found")
        if is_enabled and not config.is_enabled:
            raise NotificationValidationError("Notification config is disabled")

        updated = NotificationRule(
            id=existing.id,
            user_id=existing.user_id,
            name=name,
            scope=scope,
            is_enabled=is_enabled,
            config_id=config_id,
            severity_min=severity_min,
            event_types_json=json.dumps(event_types),
            rate_limit_per_hour=rate_limit_per_hour,
            created_at=existing.created_at,
            updated_at=timestamp,
        )

        saved = self.notification_rule_repository.update(updated)
        return self._rule_to_public_dict(saved)

    def delete_rule(self, user_id: str, rule_id: str) -> bool:
        return self.notification_rule_repository.delete(user_id, rule_id)

    # -------------------------------------------------------------------------
    # Events
    # -------------------------------------------------------------------------

    def list_events(self, user_id: str, limit: int = 50) -> list[dict]:
        events = self.notification_event_repository.list_for_user(user_id, limit=limit)
        return [self._event_to_public_dict(event) for event in events]

    def create_event(
        self,
        user_id: str,
        type: str,
        severity: str,
        title: str,
        message: str,
        job_id: str | None = None,
        payload: dict | None = None,
        scope: str = "user",
    ) -> dict:
        timestamp = now()
        severity = self._validate_severity(severity)
        scope = self._validate_scope(scope)

        matched_rules = self._match_rules(
            user_id=user_id,
            event_type=type,
            severity=severity,
            scope=scope,
        )

        config_ids = []
        rule_ids = []
        seen_config_ids = set()
        seen_rule_ids = set()

        for rule in matched_rules:
            rule_id = str(rule.id or "").strip()
            config_id = str(rule.config_id or "").strip()

            if rule_id and rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                rule_ids.append(rule_id)

            if config_id and config_id not in seen_config_ids:
                seen_config_ids.add(config_id)
                config_ids.append(config_id)

        event = NotificationEvent(
            id=str(uuid.uuid4()),
            user_id=user_id,
            job_id=job_id,
            type=self._require_text(type, "type"),
            severity=severity,
            title=self._require_text(title, "title"),
            message=self._require_text(message, "message"),
            payload_json=json.dumps(payload or {}),
            status="pending" if rule_ids else "ignored",
            attempts=0,
            max_attempts=5,
            last_error=None,
            triggered_by_rule_ids_json=json.dumps(rule_ids),
            triggered_by_config_ids_json=json.dumps(config_ids),
            next_retry_at=None,
            created_at=timestamp,
            updated_at=timestamp,
            sent_at=None,
        )

        saved = self.notification_event_repository.create(event)
        return self._event_to_public_dict(saved)

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _match_rules(self, user_id: str, event_type: str, severity: str, scope: str) -> list[NotificationRule]:
        rules = self.notification_rule_repository.list_enabled_for_user(user_id, scope=scope)
        matched = []

        event_rank = self._severity_rank(severity)

        for rule in rules:
            if event_rank < self._severity_rank(rule.severity_min):
                continue

            event_types = json.loads(rule.event_types_json or "[]")
            if event_types and event_type not in event_types:
                continue

            config = self.notification_config_repository.get_by_id(user_id, rule.config_id)
            if not config or not config.is_enabled:
                continue

            matched.append(rule)

        return matched

    def _serialize_config(
        self,
        channel: str,
        config_payload: dict | None,
        existing_config: NotificationConfig | None,
    ) -> str:
        return serialize_config(
            self._decode_config,
            self._encode_config,
            channel,
            config_payload,
            existing_config,
        )

    def _encode_config(self, config: dict) -> str:
        return encode_config(self.crypto_service, config)

    def _decode_config(self, config_json: str) -> dict:
        return decode_config(self.crypto_service, config_json)

    def _config_to_public_dict(self, config: NotificationConfig) -> dict:
        return config_to_public_dict(self._decode_config, config)

    def _rule_to_public_dict(self, rule: NotificationRule) -> dict:
        return rule_to_public_dict(rule)

    def _event_to_public_dict(self, event: NotificationEvent) -> dict:
        return event_to_public_dict(event)

    def _safe_config(self, channel: str, config: dict) -> dict:
        return safe_config(channel, config)

    def _require_text(self, value, field_name: str) -> str:
        return require_text(value, field_name)

    def _validate_channel(self, value) -> str:
        return validate_channel(value)

    def _validate_severity(self, value) -> str:
        return validate_severity(value)

    def _validate_scope(self, value) -> str:
        return validate_scope(value)

    def _validate_event_types(self, value) -> list[str]:
        return validate_event_types(value)

    def _validate_rate_limit(self, value) -> int:
        return validate_rate_limit(value)

    def _severity_rank(self, severity: str) -> int:
        return severity_rank(severity)

    def list_all_events_admin(self, limit: int = 100, status: str | None = None) -> list[dict]:
        limit = int(limit)

        if limit < 1:
            raise NotificationValidationError("limit must be >= 1")

        if limit > 500:
            raise NotificationValidationError("limit must be <= 500")

        clean_status = str(status or "").strip().lower() or None

        if clean_status and clean_status not in {
            "pending",
            "sent",
            "retrying",
            "failed",
            "ignored",
        }:
            raise NotificationValidationError("Unsupported notification event status")

        if not hasattr(self.notification_event_repository, "list_all"):
            raise NotificationValidationError("Notification event repository does not support admin listing")

        events = self.notification_event_repository.list_all(
            limit=limit,
            status=clean_status,
        )

        return [self._event_to_public_dict(event) for event in events]