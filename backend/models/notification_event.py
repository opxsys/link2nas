from dataclasses import dataclass


@dataclass
class NotificationEvent:
    id: str
    user_id: str
    job_id: str | None
    type: str
    severity: str
    title: str
    message: str
    payload_json: str
    status: str
    attempts: int
    max_attempts: int
    last_error: str | None
    triggered_by_rule_ids_json: str
    triggered_by_config_ids_json: str
    next_retry_at: str | None
    created_at: str
    updated_at: str
    sent_at: str | None