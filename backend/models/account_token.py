from dataclasses import dataclass


@dataclass
class AccountToken:
    id: str
    user_id: str
    token_hash: str
    token_type: str
    expires_at: str
    used_at: str | None
    created_at: str
    created_by_user_id: str | None = None
    metadata_json: str = "{}"
