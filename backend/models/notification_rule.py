from dataclasses import dataclass


@dataclass
class NotificationRule:
    id: str
    user_id: str
    name: str
    scope: str
    is_enabled: bool
    config_id: str
    severity_min: str
    event_types_json: str
    rate_limit_per_hour: int
    created_at: str
    updated_at: str
