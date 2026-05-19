from dataclasses import dataclass


@dataclass
class AnnouncementRead:
    id: str
    announcement_id: str
    user_id: str
    created_at: str
    updated_at: str
    opened_at: str | None = None
    read_at: str | None = None
    acknowledged_at: str | None = None
    email_sent_at: str | None = None
    email_status: str | None = None
    email_error: str | None = None
