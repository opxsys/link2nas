import uuid

from backend.models.notification_config import NotificationConfig
from backend.models.notification_rule import NotificationRule
from backend.services_v2.notification_support.validation import NotificationValidationError
from backend.utils.time import utc_now_iso as now


def create_config_impl(
    notification_config_repository,
    require_text_func,
    validate_channel_func,
    serialize_config_func,
    config_to_public_dict_func,
    smtp_service,
    user_id: str,
    payload: dict,
) -> dict:
    timestamp = now()

    name = require_text_func(payload.get("name"), "name")
    channel = validate_channel_func(payload.get("channel"))

    if channel == "email" and smtp_service and not smtp_service.is_email_sending_available():
        raise NotificationValidationError("Email sending is not configured.")

    is_enabled = bool(payload.get("is_enabled", True))
    is_default = bool(payload.get("is_default", False))

    config_payload = payload.get("config") or {}
    config_json = serialize_config_func(channel, config_payload, existing_config=None)

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

    saved = notification_config_repository.create(config)
    return config_to_public_dict_func(saved)


def update_config_impl(
    notification_config_repository,
    notification_rule_repository,
    require_text_func,
    validate_channel_func,
    serialize_config_func,
    config_to_public_dict_func,
    not_found_error_class,
    user_id: str,
    config_id: str,
    payload: dict,
) -> dict:
    existing = notification_config_repository.get_by_id(user_id, config_id)

    if not existing:
        raise not_found_error_class("Notification config not found")

    timestamp = now()

    name = require_text_func(payload.get("name", existing.name), "name")
    channel = validate_channel_func(payload.get("channel", existing.channel))
    is_enabled = bool(payload.get("is_enabled", existing.is_enabled))
    is_default = bool(payload.get("is_default", existing.is_default))

    config_payload = payload.get("config")
    config_json = serialize_config_func(
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

    saved = notification_config_repository.update(updated)

    if not is_enabled:
        timestamp_rules = now()
        for rule in notification_rule_repository.list_for_user(user_id):
            if rule.config_id == config_id and rule.is_enabled:
                notification_rule_repository.update(NotificationRule(
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

    return config_to_public_dict_func(saved)
