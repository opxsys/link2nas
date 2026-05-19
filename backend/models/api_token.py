from dataclasses import dataclass


@dataclass
class ApiToken:
    id: str
    user_id: str
    token: str
    label: str | None
    is_active: bool
    created_at: str
    updated_at: str
