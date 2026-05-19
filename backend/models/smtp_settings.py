from dataclasses import dataclass


@dataclass
class SmtpSettings:
    id: str
    enabled: bool

    host: str | None
    port: int

    username: str | None
    encrypted_password: str | None

    from_email: str | None
    from_name: str | None

    use_tls: bool
    use_ssl: bool

    created_at: str
    updated_at: str
