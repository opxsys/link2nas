from backend.utils.email_templates import build_announcement_email, _ANNOUNCEMENT_ACTION_TEXTS
from backend.services_v2.smtp_service import SmtpServiceError
from backend.utils.user_language import resolve_preferred_language
from backend.services_v2.announcement_support.constants import AnnouncementEmailUnavailableError
from backend.services_v2.announcement_support.tracking import get_or_create_read


def send_announcement_emails(
    ann,
    smtp_service,
    app_settings_service,
    email_template_svc,
    user_repo,
    read_repo,
    now_func,
) -> None:
    if not smtp_service or not smtp_service.is_email_sending_available():
        raise AnnouncementEmailUnavailableError(
            "SMTP is not configured or not enabled"
        )

    app_name = "Link2NAS"
    url = ""
    if app_settings_service:
        try:
            app_name = app_settings_service.get_effective_app_name() or "Link2NAS"
            url = app_settings_service.get_effective_public_base_url() or ""
        except Exception:
            pass

    users = user_repo.list_all()
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

            if email_template_svc:
                subject, body_text = email_template_svc.render(
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

            smtp_service.send_email(user.email, subject, body_text)
            read = get_or_create_read(read_repo, ann.id, user.id, now_func)
            now = now_func()
            if read.opened_at is None:
                read.opened_at = now
            if read.email_sent_at is None:
                read.email_sent_at = now
            read.email_status = "sent"
            read.email_error = None
            read.updated_at = now
            read_repo.upsert(read)
        except SmtpServiceError as exc:
            read = get_or_create_read(read_repo, ann.id, user.id, now_func)
            now = now_func()
            read.email_status = "failed"
            read.email_error = str(exc)
            read.updated_at = now
            read_repo.upsert(read)
        except Exception as exc:
            read = get_or_create_read(read_repo, ann.id, user.id, now_func)
            now = now_func()
            read.email_status = "failed"
            read.email_error = f"Unexpected error: {exc}"
            read.updated_at = now
            read_repo.upsert(read)
