import uuid

from backend.models.announcement_read import AnnouncementRead
from backend.services_v2.announcement_support.serialization import serialize_announcement


def get_or_create_read(read_repo, announcement_id: str, user_id: str, now_func) -> AnnouncementRead:
    read = read_repo.get(announcement_id, user_id)
    if read is None:
        now = now_func()
        read = AnnouncementRead(
            id=str(uuid.uuid4()),
            announcement_id=announcement_id,
            user_id=user_id,
            created_at=now,
            updated_at=now,
        )
    return read


def count_targeted_email_recipients(all_users) -> int:
    return sum(
        1 for u in all_users
        if u.is_active
        and u.email
        and bool(u.email_verified_at)
        and u.receive_application_emails
    )


def build_tracking_payload(announcement, stats: dict, reads, all_users) -> dict:
    targeted_email_recipients = count_targeted_email_recipients(all_users)

    user_map = {u.id: u for u in all_users}
    read_details = []
    for r in reads:
        u = user_map.get(r.user_id)
        read_details.append({
            "user_id": r.user_id,
            "email": u.email if u else None,
            "display_name": u.display_name if u else None,
            "opened_at": r.opened_at,
            "read_at": r.read_at,
            "acknowledged_at": r.acknowledged_at,
            "email_sent_at": r.email_sent_at,
            "email_status": r.email_status,
            "email_error": r.email_error,
        })

    return {
        "announcement": serialize_announcement(announcement),
        "stats": {
            **stats,
            "targeted_email_recipients": targeted_email_recipients,
        },
        "reads": read_details,
    }
