import json
import uuid

from backend.models.notification_rule import NotificationRule
from backend.services_v2.notification_support.validation import NotificationValidationError
from backend.utils.time import utc_now_iso as now


def create_rule_impl(
    notification_config_repository,
    notification_rule_repository,
    require_text_func,
    validate_scope_func,
    validate_severity_func,
    validate_event_types_func,
    validate_rate_limit_func,
    rule_to_public_dict_func,
    user_id: str,
    payload: dict,
) -> dict:
    timestamp = now()

    name = require_text_func(payload.get("name"), "name")
    scope = validate_scope_func(payload.get("scope", "user"))
    is_enabled = bool(payload.get("is_enabled", True))
    config_id = require_text_func(payload.get("config_id"), "config_id")
    severity_min = validate_severity_func(payload.get("severity_min", "info"))
    event_types = validate_event_types_func(payload.get("event_types", []))
    rate_limit_per_hour = validate_rate_limit_func(payload.get("rate_limit_per_hour", 30))

    config = notification_config_repository.get_by_id(user_id, config_id)
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

    saved = notification_rule_repository.create(rule)
    return rule_to_public_dict_func(saved)


def update_rule_impl(
    notification_config_repository,
    notification_rule_repository,
    require_text_func,
    validate_scope_func,
    validate_severity_func,
    validate_event_types_func,
    validate_rate_limit_func,
    rule_to_public_dict_func,
    not_found_error_class,
    user_id: str,
    rule_id: str,
    payload: dict,
) -> dict:
    existing = notification_rule_repository.get_by_id(user_id, rule_id)

    if not existing:
        raise not_found_error_class("Notification rule not found")

    timestamp = now()

    name = require_text_func(payload.get("name", existing.name), "name")
    scope = validate_scope_func(payload.get("scope", existing.scope))
    is_enabled = bool(payload.get("is_enabled", existing.is_enabled))
    config_id = require_text_func(payload.get("config_id", existing.config_id), "config_id")
    severity_min = validate_severity_func(payload.get("severity_min", existing.severity_min))
    event_types = validate_event_types_func(
        payload.get("event_types", json.loads(existing.event_types_json or "[]"))
    )
    rate_limit_per_hour = validate_rate_limit_func(
        payload.get("rate_limit_per_hour", existing.rate_limit_per_hour)
    )

    config = notification_config_repository.get_by_id(user_id, config_id)
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

    saved = notification_rule_repository.update(updated)
    return rule_to_public_dict_func(saved)
