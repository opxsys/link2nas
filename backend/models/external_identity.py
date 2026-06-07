from dataclasses import dataclass


@dataclass
class ExternalIdentity:
    id: str
    user_id: str
    provider: str
    issuer: str
    subject: str
    linked_at: str
    email: str | None = None
    last_used_at: str | None = None
