from dataclasses import dataclass


@dataclass
class Announcement:
    id: str
    title: str
    body: str
    type: str
    severity: str
    is_active: bool
    show_as_banner: bool
    require_acknowledgement: bool
    track_open: bool
    send_email: bool
    created_at: str
    updated_at: str
    starts_at: str | None = None
    ends_at: str | None = None
    deleted_at: str | None = None
    created_by_user_id: str | None = None
