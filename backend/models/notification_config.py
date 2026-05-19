from dataclasses import dataclass


@dataclass
class NotificationConfig:
    id: str
    user_id: str
    name: str
    channel: str
    is_enabled: bool
    is_default: bool
    config_json: str
    created_at: str
    updated_at: str