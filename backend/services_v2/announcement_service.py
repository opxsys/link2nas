import uuid
from backend.utils.time import utc_now_iso

from backend.models.announcement import Announcement
from backend.models.announcement_read import AnnouncementRead
from backend.services_v2.announcement_support.constants import (
    VALID_TYPES,
    VALID_SEVERITIES,
    AnnouncementEmailUnavailableError,
)
from backend.services_v2.announcement_support.serialization import (
    serialize_announcement,
    serialize_announcement_with_read,
)
from backend.services_v2.announcement_support.validation import (
    validate_announcement_payload,
    validate_announcement_dates,
)
from backend.services_v2.announcement_support.email_delivery import send_announcement_emails
from backend.services_v2.announcement_support.tracking import (
    get_or_create_read,
    build_tracking_payload,
)


_now = utc_now_iso


class AnnouncementService:
    def __init__(
        self,
        announcement_repository,
        announcement_read_repository,
        user_repository,
        smtp_service=None,
        app_settings_service=None,
        email_template_service=None,
    ):
        self.ann_repo = announcement_repository
        self.read_repo = announcement_read_repository
        self.user_repo = user_repository
        self.smtp_service = smtp_service
        self.app_settings_service = app_settings_service
        self.email_template_svc = email_template_service

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def _serialize(self, a: Announcement) -> dict:
        return serialize_announcement(a)

    def _serialize_with_read(self, a: Announcement, read: AnnouncementRead | None) -> dict:
        return serialize_announcement_with_read(a, read)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, data: dict) -> None:
        validate_announcement_payload(data)

    # ------------------------------------------------------------------
    # Feature flag
    # ------------------------------------------------------------------

    def is_enabled(self) -> bool:
        if not self.app_settings_service:
            return True
        try:
            return self.app_settings_service.is_announcements_enabled()
        except Exception:
            return True

    # ------------------------------------------------------------------
    # User-facing reads
    # ------------------------------------------------------------------

    def list_active(self, user_id: str) -> list[dict]:
        now = _now()
        announcements = self.ann_repo.list_active(now)
        if not announcements:
            return []
        reads = self.read_repo.list_for_user(user_id)
        reads_by_id = {r.announcement_id: r for r in reads}
        return [
            self._serialize_with_read(a, reads_by_id.get(a.id))
            for a in announcements
        ]

    def list_all_with_user_status(self, user_id: str) -> list[dict]:
        announcements = self.ann_repo.list_all()
        if not announcements:
            return []
        reads = self.read_repo.list_for_user(user_id)
        reads_by_id = {r.announcement_id: r for r in reads}
        return [
            self._serialize_with_read(a, reads_by_id.get(a.id))
            for a in announcements
        ]

    # ------------------------------------------------------------------
    # Admin reads
    # ------------------------------------------------------------------

    def list_admin(self) -> list[dict]:
        return [self._serialize(a) for a in self.ann_repo.list_all()]

    def get_admin(self, announcement_id: str) -> dict | None:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None or a.deleted_at is not None:
            return None
        return self._serialize(a)

    # ------------------------------------------------------------------
    # Admin mutations
    # ------------------------------------------------------------------

    def create(self, data: dict, created_by_user_id: str) -> dict:
        self._validate(data)
        validate_announcement_dates(data)

        title = str(data.get("title") or "").strip()
        if not title:
            raise ValueError("Title is required")

        body = str(data.get("body") or "").strip()
        if not body:
            raise ValueError("Body is required")

        ann_type = str(data.get("type") or "news")
        if ann_type not in VALID_TYPES:
            raise ValueError(
                f"Invalid type '{ann_type}'. Must be one of: {', '.join(sorted(VALID_TYPES))}"
            )

        severity = str(data.get("severity") or "info")
        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )

        now = _now()
        a = Announcement(
            id=str(uuid.uuid4()),
            title=title,
            body=body,
            type=ann_type,
            severity=severity,
            is_active=bool(data.get("is_active", True)),
            show_as_banner=bool(data.get("show_as_banner", False)),
            require_acknowledgement=bool(data.get("require_acknowledgement", False)),
            track_open=bool(data.get("track_open", False)),
            send_email=bool(data.get("send_email", False)),
            starts_at=data.get("starts_at") or None,
            ends_at=data.get("ends_at") or None,
            created_by_user_id=created_by_user_id,
            created_at=now,
            updated_at=now,
        )
        self.ann_repo.create(a)
        if a.send_email and self.is_enabled():
            self._send_announcement_emails(a)
        return self._serialize(a)

    def update(self, announcement_id: str, data: dict) -> dict | None:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None or a.deleted_at is not None:
            return None

        self._validate(data)
        validate_announcement_dates(data, existing=a)

        if "title" in data:
            title = str(data["title"] or "").strip()
            if not title:
                raise ValueError("Title cannot be empty")
            a.title = title

        if "body" in data:
            body = str(data["body"] or "").strip()
            if not body:
                raise ValueError("Body cannot be empty")
            a.body = body

        if "type" in data:
            a.type = str(data["type"])
        if "severity" in data:
            a.severity = str(data["severity"])
        if "is_active" in data:
            a.is_active = bool(data["is_active"])
        if "show_as_banner" in data:
            a.show_as_banner = bool(data["show_as_banner"])
        if "require_acknowledgement" in data:
            a.require_acknowledgement = bool(data["require_acknowledgement"])
        if "track_open" in data:
            a.track_open = bool(data["track_open"])
        if "send_email" in data:
            a.send_email = bool(data["send_email"])
        if "starts_at" in data:
            a.starts_at = data["starts_at"] or None
        if "ends_at" in data:
            a.ends_at = data["ends_at"] or None

        a.updated_at = _now()
        self.ann_repo.update(a)
        return self._serialize(a)

    def soft_delete(self, announcement_id: str) -> bool:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None or a.deleted_at is not None:
            return False
        self.ann_repo.delete(announcement_id)
        return True

    # ------------------------------------------------------------------
    # Email delivery
    # ------------------------------------------------------------------

    def _send_announcement_emails(self, ann: Announcement) -> None:
        send_announcement_emails(
            ann,
            smtp_service=self.smtp_service,
            app_settings_service=self.app_settings_service,
            email_template_svc=self.email_template_svc,
            user_repo=self.user_repo,
            read_repo=self.read_repo,
            now_func=_now,
        )

    # ------------------------------------------------------------------
    # User tracking
    # ------------------------------------------------------------------

    def _get_or_create_read(self, announcement_id: str, user_id: str) -> AnnouncementRead:
        return get_or_create_read(self.read_repo, announcement_id, user_id, _now)

    def mark_opened(self, announcement_id: str, user_id: str) -> bool:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None or a.deleted_at is not None:
            return False
        if not a.track_open:
            return True
        read = self._get_or_create_read(announcement_id, user_id)
        if read.opened_at is None:
            read.opened_at = _now()
            read.updated_at = _now()
        self.read_repo.upsert(read)
        return True

    def mark_read(self, announcement_id: str, user_id: str) -> bool:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None or a.deleted_at is not None:
            return False
        read = self._get_or_create_read(announcement_id, user_id)
        if read.read_at is None:
            read.read_at = _now()
            read.updated_at = _now()
        self.read_repo.upsert(read)
        return True

    def mark_acknowledged(self, announcement_id: str, user_id: str) -> bool:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None or a.deleted_at is not None:
            return False
        if not a.require_acknowledgement:
            raise ValueError("This announcement does not require acknowledgement")
        read = self._get_or_create_read(announcement_id, user_id)
        now = _now()
        changed = False
        if a.track_open and read.opened_at is None:
            read.opened_at = now
            changed = True
        if read.read_at is None:
            read.read_at = now
            changed = True
        if read.acknowledged_at is None:
            read.acknowledged_at = now
            changed = True
        if changed:
            read.updated_at = now
        self.read_repo.upsert(read)
        return True

    # ------------------------------------------------------------------
    # Admin tracking
    # ------------------------------------------------------------------

    def get_tracking(self, announcement_id: str) -> dict | None:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None:
            return None

        stats = self.read_repo.count_stats(announcement_id)
        reads = self.read_repo.list_for_announcement(announcement_id)
        all_users = self.user_repo.list_all()

        return build_tracking_payload(a, stats, reads, all_users)
