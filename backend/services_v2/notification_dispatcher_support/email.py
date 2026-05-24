import json

from backend.services_v2.smtp_service import SmtpServiceError
from backend.services_v2.notification_dispatcher_support.content import build_user_summary, resolve_job_name


def send_email(
    cfg: dict,
    config,
    event,
    smtp_service,
    user_repository=None,
    email_template_service=None,
    app_settings_service=None,
    job_repository=None,
) -> None:
    if not smtp_service:
        raise RuntimeError("SMTP service is not configured")

    to_email = str(cfg.get("to_email") or "").strip()
    user = None

    if not to_email:
        if not user_repository:
            raise RuntimeError("User repository is not configured")

        user_id = str(getattr(event, "user_id", "") or "").strip()
        user = user_repository.get_by_id(user_id) if user_id else None
        to_email = str(getattr(user, "email", None) or "").strip() if user else ""

    if not to_email:
        raise ValueError("Email target is required")

    title = str(getattr(event, "title", None) or "Link2NAS notification").strip()
    message = str(getattr(event, "message", None) or "").strip()
    event_type = str(getattr(event, "type", None) or "").strip()
    severity = str(getattr(event, "severity", None) or "").strip()
    job_id = str(getattr(event, "job_id", None) or "").strip()
    event_id = str(getattr(event, "id", None) or "").strip()
    config_name = str(getattr(config, "name", None) or "").strip()
    created_at = str(getattr(event, "created_at", None) or "").strip()

    if email_template_service:
        app_name = "Link2NAS"
        if app_settings_service:
            try:
                app_name = app_settings_service.get_effective_app_name() or "Link2NAS"
            except Exception:
                pass

        if user is None and user_repository:
            try:
                uid = str(getattr(event, "user_id", "") or "").strip()
                if uid:
                    user = user_repository.get_by_id(uid)
            except Exception:
                pass

        lang = getattr(user, "preferred_language", None) if user else None

        provider_payload: dict = {}
        if job_id and job_repository:
            try:
                uid = str(getattr(event, "user_id", "") or "").strip()
                job = job_repository.get_by_id(uid, job_id) if uid else None
                raw = str(getattr(job, "provider_payload_json", None) or "").strip() if job else ""
                provider_payload = json.loads(raw) if raw else {}
            except Exception:
                provider_payload = {}

        job_name = resolve_job_name(provider_payload, job_id or None, lang)
        user_summary = build_user_summary(event_type, title, message, lang)

        subject, body = email_template_service.render(
            "notification_event",
            lang,
            app_name=app_name,
            title=title,
            message=message,
            event_type=event_type,
            severity=severity,
            job_id=job_id,
            job_name=job_name,
            event_id=event_id,
            config_name=config_name,
            created_at=created_at,
            user_summary=user_summary,
        )
    else:
        job_name = resolve_job_name({}, job_id or None, None)
        body_parts = [
            message,
            "",
            f"Job: {job_name}" if job_name else "",
            f"Type: {event_type}" if event_type else "",
            f"Severity: {severity}" if severity else "",
            f"Job ID: {job_id}" if job_id else "",
            f"Event ID: {event_id}",
            f"Config: {config_name}",
        ]
        body = "\n".join(part for part in body_parts if part is not None).strip()
        subject = f"Link2NAS - {title}"

    try:
        smtp_service.send_email(
            to_email=to_email,
            subject=subject,
            body=body,
        )
    except SmtpServiceError as exc:
        raise RuntimeError(str(exc)) from exc
