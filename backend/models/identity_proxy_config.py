from dataclasses import dataclass


@dataclass
class IdentityProxyConfig:
    id: str
    name: str
    provider_type: str
    enabled: bool
    label: str
    auto_login: bool
    auto_create_users: bool
    allowed_domains_json: str  # JSON array string, e.g. '[]' or '["example.com"]'
    config_json: str           # provider-specific config, e.g. '{"team_domain": "...", "audience": "..."}'
    created_at: str
    updated_at: str
