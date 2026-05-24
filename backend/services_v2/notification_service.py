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
)
from backend.services_v2.notification_support.config_codec import encode_config, decode_config
from backend.services_v2.notification_support.config_serialization import serialize_config
from backend.services_v2.notification_support.test_config import (
    test_config_email,
    test_config_gotify,
    test_config_webhook,
)
from backend.services_v2.notification_support.admin_events import list_all_events_admin_impl
from backend.services_v2.notification_support.events import create_event_impl
from backend.services_v2.notification_support.rules import create_rule_impl, update_rule_impl
from backend.services_v2.notification_support.configs import create_config_impl, update_config_impl
from backend.services_v2.notification_support.rule_matching import match_rules_impl


class NotificationNotFoundError(Exception):
    pass


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
        return create_config_impl(
            self.notification_config_repository,
            self._require_text,
            self._validate_channel,
            self._serialize_config,
            self._config_to_public_dict,
            self.smtp_service,
            user_id,
            payload,
        )

    def update_config(self, user_id: str, config_id: str, payload: dict) -> dict:
        return update_config_impl(
            self.notification_config_repository,
            self.notification_rule_repository,
            self._require_text,
            self._validate_channel,
            self._serialize_config,
            self._config_to_public_dict,
            NotificationNotFoundError,
            user_id,
            config_id,
            payload,
        )

    def delete_config(self, user_id: str, config_id: str) -> bool:
        return self.notification_config_repository.delete(user_id, config_id)
        
    def test_config(self, user_id: str, config_id: str) -> dict:
        config = self.notification_config_repository.get_by_id(user_id, config_id)

        if not config:
            raise NotificationNotFoundError("Notification config not found")

        decoded = self._decode_config(config.config_json)
        channel = self._validate_channel(config.channel)

        if channel == "email":
            return test_config_email(
                config,
                decoded,
                user_id,
                self.smtp_service,
                self.user_repository,
                self.email_template_service,
                self.app_settings_service,
                SmtpServiceError,
            )
        if channel == "gotify":
            return test_config_gotify(config, decoded)

        if channel == "webhook":
            return test_config_webhook(config, decoded)

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
        return create_rule_impl(
            self.notification_config_repository,
            self.notification_rule_repository,
            self._require_text,
            self._validate_scope,
            self._validate_severity,
            self._validate_event_types,
            self._validate_rate_limit,
            self._rule_to_public_dict,
            user_id,
            payload,
        )

    def update_rule(self, user_id: str, rule_id: str, payload: dict) -> dict:
        return update_rule_impl(
            self.notification_config_repository,
            self.notification_rule_repository,
            self._require_text,
            self._validate_scope,
            self._validate_severity,
            self._validate_event_types,
            self._validate_rate_limit,
            self._rule_to_public_dict,
            NotificationNotFoundError,
            user_id,
            rule_id,
            payload,
        )

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
        return create_event_impl(
            self.notification_event_repository,
            self._match_rules,
            self._event_to_public_dict,
            self._require_text,
            self._validate_severity,
            self._validate_scope,
            user_id=user_id,
            type=type,
            severity=severity,
            title=title,
            message=message,
            job_id=job_id,
            payload=payload,
            scope=scope,
        )

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _match_rules(self, user_id: str, event_type: str, severity: str, scope: str) -> list[NotificationRule]:
        return match_rules_impl(
            self.notification_rule_repository,
            self.notification_config_repository,
            self._severity_rank,
            user_id,
            event_type,
            severity,
            scope,
        )

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
        return list_all_events_admin_impl(
            self.notification_event_repository,
            self._event_to_public_dict,
            limit=limit,
            status=status,
        )