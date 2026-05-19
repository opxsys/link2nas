from backend.utils.user_language import resolve_preferred_language


_TEMPLATES = {
    "invitation": {
        "fr": {
            "subject": "Invitation {app_name}",
            "body": (
                "Bonjour,\n\n"
                "Un compte {app_name} a été créé pour cette adresse email.\n\n"
                "Pour activer votre compte et définir votre mot de passe, ouvrez ce lien :\n"
                "{url}\n\n"
                "Ce lien expire le : {expires_at}\n\n"
                "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
            ),
        },
        "en": {
            "subject": "{app_name} Invitation",
            "body": (
                "Hello,\n\n"
                "A {app_name} account has been created for this email address.\n\n"
                "To activate your account and set your password, open this link:\n"
                "{url}\n\n"
                "This link expires on: {expires_at}\n\n"
                "If you did not request this, please ignore this email.\n"
            ),
        },
    },
    "password_reset": {
        "fr": {
            "subject": "Réinitialisation du mot de passe {app_name}",
            "body": (
                "Bonjour,\n\n"
                "Une demande de réinitialisation de mot de passe {app_name} a été générée.\n\n"
                "Pour choisir un nouveau mot de passe, ouvrez ce lien :\n"
                "{url}\n\n"
                "Ce lien expire le : {expires_at}\n\n"
                "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
            ),
        },
        "en": {
            "subject": "{app_name} Password Reset",
            "body": (
                "Hello,\n\n"
                "A {app_name} password reset request has been generated.\n\n"
                "To choose a new password, open this link:\n"
                "{url}\n\n"
                "This link expires on: {expires_at}\n\n"
                "If you did not request this, please ignore this email.\n"
            ),
        },
    },
    "email_verification": {
        "fr": {
            "subject": "Validation de votre email {app_name}",
            "body": (
                "Bonjour,\n\n"
                "Vous avez demandé la validation de votre adresse email {app_name}.\n\n"
                "Pour valider votre email, ouvrez ce lien :\n"
                "{url}\n\n"
                "Ce lien expire le : {expires_at}\n\n"
                "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
            ),
        },
        "en": {
            "subject": "{app_name} Email Verification",
            "body": (
                "Hello,\n\n"
                "You requested verification of your {app_name} email address.\n\n"
                "To verify your email, open this link:\n"
                "{url}\n\n"
                "This link expires on: {expires_at}\n\n"
                "If you did not request this, please ignore this email.\n"
            ),
        },
    },
    "magic_login": {
        "fr": {
            "subject": "Connexion {app_name}",
            "body": (
                "Bonjour,\n\n"
                "Vous avez demandé un lien de connexion {app_name}.\n\n"
                "Pour vous connecter, ouvrez ce lien :\n"
                "{url}\n\n"
                "Ce lien expire le : {expires_at}\n\n"
                "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
            ),
        },
        "en": {
            "subject": "{app_name} Login Link",
            "body": (
                "Hello,\n\n"
                "You requested a {app_name} login link.\n\n"
                "To sign in, open this link:\n"
                "{url}\n\n"
                "This link expires on: {expires_at}\n\n"
                "If you did not request this, please ignore this email.\n"
            ),
        },
    },
}

_TEMPLATES["announcement"] = {
    "fr": {
        "subject": "[{app_name}] {title}",
        "body": (
            "Bonjour,\n\n"
            "Vous avez reçu une annonce applicative.\n\n"
            "Titre :\n"
            "{title}\n\n"
            "Message :\n"
            "{body}\n\n"
            "Type : {type}\n"
            "Sévérité : {severity}\n\n"
            "{action_text}\n\n"
            "Ouvrir l'annonce :\n"
            "{url}\n\n"
            "— {app_name}\n"
        ),
    },
    "en": {
        "subject": "[{app_name}] {title}",
        "body": (
            "Hello,\n\n"
            "You have received an application announcement.\n\n"
            "Title:\n"
            "{title}\n\n"
            "Message:\n"
            "{body}\n\n"
            "Type: {type}\n"
            "Severity: {severity}\n\n"
            "{action_text}\n\n"
            "Open the announcement:\n"
            "{url}\n\n"
            "— {app_name}\n"
        ),
    },
}

_TEMPLATES["smtp_test"] = {
    "fr": {
        "subject": "{app_name} — Test SMTP",
        "body": (
            "Ceci est un email de test {app_name}.\n\n"
            "Si vous recevez ce message, la configuration SMTP fonctionne correctement."
        ),
    },
    "en": {
        "subject": "{app_name} — SMTP Test",
        "body": (
            "This is a test email from {app_name}.\n\n"
            "If you receive this message, your SMTP configuration is working correctly."
        ),
    },
}

_TEMPLATES["notification_event"] = {
    "fr": {
        "subject": "[{app_name}] {user_summary}",
        "body": (
            "Job : {job_name}\n\n"
            "{user_summary}\n\n"
            "Détails techniques :\n"
            "- Type : {event_type}\n"
            "- Sévérité : {severity}\n"
            "- Job ID : {job_id}\n"
            "- Événement ID : {event_id}\n"
            "- Configuration : {config_name}\n"
            "- Date : {created_at}\n\n"
            "— {app_name}"
        ),
    },
    "en": {
        "subject": "[{app_name}] {user_summary}",
        "body": (
            "Job: {job_name}\n\n"
            "{user_summary}\n\n"
            "Technical details:\n"
            "- Type: {event_type}\n"
            "- Severity: {severity}\n"
            "- Job ID: {job_id}\n"
            "- Event ID: {event_id}\n"
            "- Config: {config_name}\n"
            "- Date: {created_at}\n\n"
            "— {app_name}"
        ),
    },
}

_TEMPLATES["notification_test"] = {
    "fr": {
        "subject": "[{app_name}] Test notification",
        "body": (
            "Ceci est un email de test pour le canal de notification « {channel_name} ».\n\n"
            "Canal : {channel}\n"
            "Destinataire : {to_email}\n"
            "Configuration : {config_id}\n\n"
            "Si vous recevez ce message, la configuration email fonctionne correctement.\n\n"
            "— {app_name}"
        ),
    },
    "en": {
        "subject": "[{app_name}] Test notification",
        "body": (
            'This is a test email for notification channel "{channel_name}".\n\n'
            "Channel: {channel}\n"
            "Recipient: {to_email}\n"
            "Config ID: {config_id}\n\n"
            "If you receive this message, the email notification configuration is working correctly.\n\n"
            "— {app_name}"
        ),
    },
}

_ANNOUNCEMENT_ACTION_TEXTS = {
    "fr": {
        True: "Cette annonce nécessite une confirmation de prise de connaissance.",
        False: "Vous pouvez la marquer comme lue depuis l'application.",
    },
    "en": {
        True: "This announcement requires acknowledgement.",
        False: "You can mark it as read in the application.",
    },
}

EMAIL_TEMPLATE_VARIABLES = {
    "invitation": ("url", "expires_at", "app_name"),
    "password_reset": ("url", "expires_at", "app_name"),
    "email_verification": ("url", "expires_at", "app_name"),
    "magic_login": ("url", "expires_at", "app_name"),
    "smtp_test": ("app_name", "public_base_url"),
    "announcement": ("app_name", "title", "body", "type", "severity", "url", "action_text", "starts_at", "ends_at"),
    "notification_event": ("app_name", "title", "message", "event_type", "severity", "job_id", "job_name", "event_id", "config_name", "created_at", "user_summary"),
    "notification_test": ("app_name", "channel_name", "channel", "to_email", "config_id", "public_base_url"),
}

EMAIL_TEMPLATE_SAMPLE_VALUES = {
    "invitation": {
        "app_name": "Link2NAS",
        "url": "https://link2nas.example.com/invite?token=sample",
        "expires_at": "2026-01-01T12:00:00+00:00",
    },
    "password_reset": {
        "app_name": "Link2NAS",
        "url": "https://link2nas.example.com/reset-password?token=sample",
        "expires_at": "2026-01-01T12:00:00+00:00",
    },
    "email_verification": {
        "app_name": "Link2NAS",
        "url": "https://link2nas.example.com/verify-email?token=sample",
        "expires_at": "2026-01-01T12:00:00+00:00",
    },
    "magic_login": {
        "app_name": "Link2NAS",
        "url": "https://link2nas.example.com/magic-login?token=sample",
        "expires_at": "2026-01-01T12:00:00+00:00",
    },
    "smtp_test": {
        "app_name": "Link2NAS",
        "public_base_url": "https://link2nas.example.com",
    },
    "announcement": {
        "app_name": "Link2NAS",
        "title": "Planned maintenance",
        "body": "A maintenance is scheduled this weekend.",
        "type": "maintenance",
        "severity": "warning",
        "url": "https://link2nas.example.com",
        "action_text": "This announcement requires acknowledgement.",
        "starts_at": "2026-01-04T08:00:00+00:00",
        "ends_at": "2026-01-04T12:00:00+00:00",
    },
    "notification_event": {
        "app_name": "Link2NAS",
        "title": "Job completed",
        "message": "Job 'Download Test' completed successfully.",
        "event_type": "job.completed",
        "severity": "info",
        "job_id": "job-uuid-1234",
        "job_name": "Download Test",
        "event_id": "event-uuid-5678",
        "config_name": "Email admin",
        "created_at": "2026-01-01T12:00:00+00:00",
        "user_summary": "Le job est terminé.",
    },
    "notification_test": {
        "app_name": "Link2NAS",
        "channel_name": "Mon canal email",
        "channel": "email",
        "to_email": "test@example.com",
        "config_id": "unsaved",
        "public_base_url": "https://link2nas.example.com",
    },
}


def build_invitation_email(
    language: str | None,
    url: str,
    expires_at: str,
    app_name: str = "Link2NAS",
) -> tuple[str, str]:
    t = _TEMPLATES["invitation"][resolve_preferred_language(language)]
    return (
        t["subject"].format(app_name=app_name),
        t["body"].format(url=url, expires_at=expires_at, app_name=app_name),
    )


def build_password_reset_email(
    language: str | None,
    url: str,
    expires_at: str,
    app_name: str = "Link2NAS",
) -> tuple[str, str]:
    t = _TEMPLATES["password_reset"][resolve_preferred_language(language)]
    return (
        t["subject"].format(app_name=app_name),
        t["body"].format(url=url, expires_at=expires_at, app_name=app_name),
    )


def build_email_verification_email(
    language: str | None,
    url: str,
    expires_at: str,
    app_name: str = "Link2NAS",
) -> tuple[str, str]:
    t = _TEMPLATES["email_verification"][resolve_preferred_language(language)]
    return (
        t["subject"].format(app_name=app_name),
        t["body"].format(url=url, expires_at=expires_at, app_name=app_name),
    )


def build_magic_login_email(
    language: str | None,
    url: str,
    expires_at: str,
    app_name: str = "Link2NAS",
) -> tuple[str, str]:
    t = _TEMPLATES["magic_login"][resolve_preferred_language(language)]
    return (
        t["subject"].format(app_name=app_name),
        t["body"].format(url=url, expires_at=expires_at, app_name=app_name),
    )


def build_announcement_email(
    language: str | None,
    *,
    app_name: str,
    title: str,
    body: str,
    type: str,
    severity: str,
    url: str,
    require_acknowledgement: bool = False,
    starts_at: str | None = None,
    ends_at: str | None = None,
) -> tuple[str, str]:
    lang = resolve_preferred_language(language)
    tmpl = _TEMPLATES["announcement"][lang]
    action_text = _ANNOUNCEMENT_ACTION_TEXTS[lang][bool(require_acknowledgement)]

    def _safe(s: str) -> str:
        return str(s or "").replace("{", "{{").replace("}", "}}")

    subject = tmpl["subject"].format(app_name=_safe(app_name), title=_safe(title))
    email_body = tmpl["body"].format(
        app_name=_safe(app_name),
        title=_safe(title),
        body=_safe(body),
        type=_safe(type),
        severity=_safe(severity),
        url=_safe(url),
        action_text=action_text,
    )
    return (subject, email_body)
