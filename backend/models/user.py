from dataclasses import dataclass


@dataclass
class User:
    id: str

    email: str
    display_name: str | None

    role: str
    is_active: bool

    created_at: str
    updated_at: str

    password_hash: str | None = None

    valid_from: str | None = None
    account_expires_at: str | None = None

    email_verified_at: str | None = None
    email_verification_token: str | None = None

    password_reset_token: str | None = None
    password_reset_sent_at: str | None = None
    force_password_change: bool = False

    last_login_at: str | None = None
    preferred_language: str | None = None
    receive_application_emails: bool = False

    public_slug: str | None = None
    can_use_local_space: bool = False
    ui_theme: str | None = None