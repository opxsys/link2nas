import uuid
from backend.utils.time import utc_now_iso

from backend.models.announcement import Announcement
from backend.models.announcement_read import AnnouncementRead

VALID_TYPES = frozenset({"news", "maintenance", "incident", "security"})
VALID_SEVERITIES = frozenset({"info", "warning", "critical"})


class AnnouncementEmailUnavailableError(Exception):
    pass


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

    def _serialize_with_read(self, a: Announcement, read: AnnouncementRead | None) -> dict:
        d = self._serialize(a)
        d["user_status"] = {
            "opened_at": read.opened_at if read else None,
            "read_at": read.read_at if read else None,
            "acknowledged_at": read.acknowledged_at if read else None,
        }
        return d

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, data: dict) -> None:
        if "type" in data and data["type"] not in VALID_TYPES:
            raise ValueError(
                f"Invalid type '{data['type']}'. Must be one of: {', '.join(sorted(VALID_TYPES))}"
            )
        if "severity" in data and data["severity"] not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{data['severity']}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )

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
        if a.send_email:
            self._send_announcement_emails(a)
        return self._serialize(a)

    def update(self, announcement_id: str, data: dict) -> dict | None:
        a = self.ann_repo.get_by_id(announcement_id)
        if a is None or a.deleted_at is not None:
            return None

        self._validate(data)

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
    # User tracking
    # ------------------------------------------------------------------

    def _send_announcement_emails(self, ann: Announcement) -> None:
        from backend.utils.email_templates import build_announcement_email, _ANNOUNCEMENT_ACTION_TEXTS
        from backend.services_v2.smtp_service import SmtpServiceError
        from backend.utils.user_language import resolve_preferred_language

        if not self.smtp_service or not self.smtp_service.is_email_sending_available():
            raise AnnouncementEmailUnavailableError(
                "SMTP is not configured or not enabled"
            )

        app_name = "Link2NAS"
        url = ""
        if self.app_settings_service:
            try:
                app_name = self.app_settings_service.get_effective_app_name() or "Link2NAS"
                url = self.app_settings_service.get_effective_public_base_url() or ""
            except Exception:
                pass

        users = self.user_repo.list_all()
        eligible = [
            u for u in users
            if u.is_active
            and u.email
            and bool(u.email_verified_at)
            and u.receive_application_emails
        ]

        for user in eligible:
            try:
                lang = resolve_preferred_language(user.preferred_language)
                action_text = _ANNOUNCEMENT_ACTION_TEXTS[lang][bool(ann.require_acknowledgement)]

                if self.email_template_svc:
                    subject, body_text = self.email_template_svc.render(
                        "announcement",
                        user.preferred_language,
                        app_name=app_name,
                        title=ann.title,
                        body=ann.body,
                        type=ann.type,
                        severity=ann.severity,
                        url=url,
                        action_text=action_text,
                        starts_at=ann.starts_at or "",
                        ends_at=ann.ends_at or "",
                    )
                else:
                    subject, body_text = build_announcement_email(
                        user.preferred_language,
                        app_name=app_name,
                        title=ann.title,
                        body=ann.body,
                        type=ann.type,
                        severity=ann.severity,
                        url=url,
                        require_acknowledgement=ann.require_acknowledgement,
                    )

                self.smtp_service.send_email(user.email, subject, body_text)
                read = self._get_or_create_read(ann.id, user.id)
                now = _now()
                if read.opened_at is None:
                    read.opened_at = now
                if read.email_sent_at is None:
                    read.email_sent_at = now
                read.email_status = "sent"
                read.email_error = None
                read.updated_at = now
                self.read_repo.upsert(read)
            except SmtpServiceError as exc:
                read = self._get_or_create_read(ann.id, user.id)
                now = _now()
                read.email_status = "failed"
                read.email_error = str(exc)
                read.updated_at = now
                self.read_repo.upsert(read)
            except Exception as exc:
                read = self._get_or_create_read(ann.id, user.id)
                now = _now()
                read.email_status = "failed"
                read.email_error = f"Unexpected error: {exc}"
                read.updated_at = now
                self.read_repo.upsert(read)

    def _get_or_create_read(self, announcement_id: str, user_id: str) -> AnnouncementRead:
        read = self.read_repo.get(announcement_id, user_id)
        if read is None:
            now = _now()
            read = AnnouncementRead(
                id=str(uuid.uuid4()),
                announcement_id=announcement_id,
                user_id=user_id,
                created_at=now,
                updated_at=now,
            )
        return read

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
        targeted_email_recipients = sum(
            1 for u in all_users
            if u.is_active
            and u.email
            and bool(u.email_verified_at)
            and u.receive_application_emails
        )

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
            "announcement": self._serialize(a),
            "stats": {
                **stats,
                "targeted_email_recipients": targeted_email_recipients,
            },
            "reads": read_details,
        }
