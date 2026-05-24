import json
import uuid

from backend.models.notification_event import NotificationEvent
from backend.utils.time import utc_now_iso as now


def create_event_impl(
    notification_event_repository,
    match_rules_func,
    event_to_public_dict_func,
    require_text_func,
    validate_severity_func,
    validate_scope_func,
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
    severity = validate_severity_func(severity)
    scope = validate_scope_func(scope)

    matched_rules = match_rules_func(
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
        type=require_text_func(type, "type"),
        severity=severity,
        title=require_text_func(title, "title"),
        message=require_text_func(message, "message"),
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

    saved = notification_event_repository.create(event)
    return event_to_public_dict_func(saved)
