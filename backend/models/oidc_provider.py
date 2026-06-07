from dataclasses import dataclass


@dataclass
class OidcProvider:
    id: str
    name: str
    slug: str
    enabled: bool
    issuer: str
    client_id: str
    scopes: str
    button_label: str
    auto_create_users: bool
    allowed_domains_json: str   # JSON array string, e.g. '[]' or '["example.com"]'
    state_ttl_seconds: int
    exchange_code_ttl_seconds: int
    sort_order: int
    created_at: str
    updated_at: str
    encrypted_client_secret: str | None = None
