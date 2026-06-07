from dataclasses import dataclass


@dataclass
class OidcState:
    id: str
    state: str
    nonce: str
    created_at: str
    expires_at: str
    exchange_code: str | None = None
    api_token_id: str | None = None
    consumed_at: str | None = None
