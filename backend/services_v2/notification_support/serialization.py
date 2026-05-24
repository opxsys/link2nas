import json

from backend.models.notification_config import NotificationConfig
from backend.models.notification_event import NotificationEvent
from backend.models.notification_rule import NotificationRule


def safe_config(channel: str, config: dict) -> dict:
    if channel == "email":
        return {
            "to_email": config.get("to_email") or "",
        }

    if channel == "gotify":
        return {
            "server_url": config.get("server_url") or "",
            "has_token": bool(config.get("token")),
        }

    if channel == "webhook":
        return {
            "url": config.get("url") or "",
            "method": config.get("method") or "POST",
            "has_headers": bool(config.get("headers")),
        }

    return {}


def config_to_public_dict(decode_config_func, config: "NotificationConfig") -> dict:
    decoded = decode_config_func(config.config_json)
    safe = safe_config(config.channel, decoded)

    return {
        "id": config.id,
        "user_id": config.user_id,
        "name": config.name,
        "channel": config.channel,
        "is_enabled": bool(config.is_enabled),
        "is_default": bool(config.is_default),
        "config": safe,
        "created_at": config.created_at,
        "updated_at": config.updated_at,
    }


def rule_to_public_dict(rule: "NotificationRule") -> dict:
    return {
        "id": rule.id,
        "user_id": rule.user_id,
        "name": rule.name,
        "scope": rule.scope,
        "is_enabled": bool(rule.is_enabled),
        "config_id": rule.config_id,
        "severity_min": rule.severity_min,
        "event_types": json.loads(rule.event_types_json or "[]"),
        "rate_limit_per_hour": int(rule.rate_limit_per_hour),
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


def event_to_public_dict(event: "NotificationEvent") -> dict:
    return {
        "id": event.id,
        "user_id": event.user_id,
        "job_id": event.job_id,
        "type": event.type,
        "severity": event.severity,
        "title": event.title,
        "message": event.message,
        "payload": json.loads(event.payload_json or "{}"),
        "status": event.status,
        "attempts": event.attempts,
        "max_attempts": event.max_attempts,
        "last_error": event.last_error,
        "triggered_by_rule_ids": json.loads(event.triggered_by_rule_ids_json or "[]"),
        "triggered_by_config_ids": json.loads(event.triggered_by_config_ids_json or "[]"),
        "next_retry_at": event.next_retry_at,
        "created_at": event.created_at,
        "updated_at": event.updated_at,
        "sent_at": event.sent_at,
    }
