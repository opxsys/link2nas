from dataclasses import dataclass


@dataclass
class ProwlarrConfig:
    id: str
    scope: str               # 'global' | 'user'
    user_id: str | None      # None for scope='global'
    enabled: bool
    base_url: str | None
    encrypted_api_key: str | None
    label: str | None        # optional display name, used for global config
    tested_at: str | None
    last_test_status: str | None
    last_test_message: str | None
    created_at: str
    updated_at: str
