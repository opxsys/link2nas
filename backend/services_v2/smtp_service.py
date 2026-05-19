import smtplib
from email.message import EmailMessage


class SmtpServiceError(Exception):
    pass


class SmtpService:
    def __init__(self, smtp_settings_repository, crypto_service):
        self.smtp_settings_repository = smtp_settings_repository
        self.crypto_service = crypto_service

    def get_settings(self):
        return self.smtp_settings_repository.get()

    def is_email_sending_available(self) -> bool:
        settings = self.smtp_settings_repository.get()
        return bool(
            settings
            and settings.enabled
            and settings.host
            and settings.port
            and settings.from_email
        )

    def send_email(self, to_email: str, subject: str, body: str) -> None:
        settings = self.smtp_settings_repository.get()

        if not settings or not settings.enabled:
            raise SmtpServiceError("SMTP is not enabled")

        if not settings.host:
            raise SmtpServiceError("SMTP host is required")

        if not settings.port:
            raise SmtpServiceError("SMTP port is required")

        if not settings.from_email:
            raise SmtpServiceError("SMTP from_email is required")

        password = self.crypto_service.decrypt(settings.encrypted_password)

        message = EmailMessage()
        message["From"] = (
            f"{settings.from_name} <{settings.from_email}>"
            if settings.from_name
            else settings.from_email
        )
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)

        try:
            if settings.use_ssl:
                with smtplib.SMTP_SSL(settings.host, settings.port, timeout=20) as smtp:
                    self._login_if_needed(smtp, settings.username, password)
                    smtp.send_message(message)
                return

            with smtplib.SMTP(settings.host, settings.port, timeout=20) as smtp:
                if settings.use_tls:
                    smtp.starttls()

                self._login_if_needed(smtp, settings.username, password)
                smtp.send_message(message)

        except Exception as exc:
            raise SmtpServiceError(f"SMTP send failed: {exc}") from exc

    def _login_if_needed(self, smtp, username, password) -> None:
        if username:
            smtp.login(username, password or "")
