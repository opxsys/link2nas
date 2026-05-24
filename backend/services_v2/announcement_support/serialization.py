from backend.models.announcement import Announcement
from backend.models.announcement_read import AnnouncementRead


def serialize_announcement(a: Announcement) -> dict:
    return {
        "id": a.id,
        "title": a.title,
        "body": a.body,
        "type": a.type,
        "severity": a.severity,
        "is_active": a.is_active,
        "show_as_banner": a.show_as_banner,
        "require_acknowledgement": a.require_acknowledgement,
        "track_open": a.track_open,
        "send_email": a.send_email,
        "starts_at": a.starts_at,
        "ends_at": a.ends_at,
        "created_by_user_id": a.created_by_user_id,
        "created_at": a.created_at,
        "updated_at": a.updated_at,
    }


def serialize_announcement_with_read(a: Announcement, read: AnnouncementRead | None) -> dict:
    d = serialize_announcement(a)
    d["user_status"] = {
        "opened_at": read.opened_at if read else None,
        "read_at": read.read_at if read else None,
        "acknowledged_at": read.acknowledged_at if read else None,
    }
    return d
