from dataclasses import dataclass


@dataclass
class UserApiKey:
    id: str
    user_id: str

    name: str
    key_prefix: str
    key_hash: str

    scopes_json: str

    is_active: bool
    revoked_at: str | None

    last_used_at: str | None
    last_used_ip: str | None
    last_used_scope: str | None

    created_at: str
    updated_at: str
