import re
import uuid
from datetime import UTC, datetime

from backend.models.email_template import EmailTemplate
from backend.utils.email_templates import (
    _TEMPLATES,
    EMAIL_TEMPLATE_VARIABLES,
    EMAIL_TEMPLATE_SAMPLE_VALUES,
)
from backend.utils.user_language import resolve_preferred_language


class EmailTemplateNotFoundError(Exception):
    pass


class EmailTemplateValidationError(ValueError):
    pass


_VAR_RE = re.compile(r"\{(\w+)\}")

SUPPORTED_LANGUAGES = ("fr", "en")


class EmailTemplateService:
    SUPPORTED_LANGUAGES = SUPPORTED_LANGUAGES
    KNOWN_KEYS = frozenset(EMAIL_TEMPLATE_VARIABLES.keys())

    def __init__(self, email_template_repository):
        self.repo = email_template_repository

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _safe(value) -> str:
        return str(value if value is not None else "").replace("{", "{{").replace("}", "}}")

    def ensure_defaults(self) -> None:
        """Insert missing templates and silently update non-custom rows that differ from code defaults."""
        now = self._now()
        for key, langs in _TEMPLATES.items():
            for lang, tmpl in langs.items():
                if lang not in SUPPORTED_LANGUAGES:
                    continue
                existing = self.repo.get(key, lang)
                if existing is None:
                    self.repo.insert_if_absent(EmailTemplate(
                        id=str(uuid.uuid4()),
                        template_key=key,
                        language=lang,
                        subject_template=tmpl["subject"],
                        body_template=tmpl["body"],
                        is_custom=False,
                        created_at=now,
                        updated_at=now,
                        updated_by_user_id=None,
                    ))
                elif not existing.is_custom and (
                    existing.subject_template != tmpl["subject"]
                    or existing.body_template != tmpl["body"]
                ):
                    self.repo.upsert(EmailTemplate(
                        id=existing.id,
                        template_key=existing.template_key,
                        language=existing.language,
                        subject_template=tmpl["subject"],
                        body_template=tmpl["body"],
                        is_custom=False,
                        created_at=existing.created_at,
                        updated_at=now,
                        updated_by_user_id=None,
                    ))

    def resolve(self, template_key: str, language: str) -> tuple[str, str]:
        """
        Returns (subject_template, body_template).
        Priority: DB[key][lang] > DB[key][en] > code[key][lang] > code[key][en].
        Raises EmailTemplateNotFoundError if nothing found.
        """
        lang = resolve_preferred_language(language)

        entry = self.repo.get(template_key, lang)
        if entry:
            return entry.subject_template, entry.body_template

        if lang != "en":
            entry = self.repo.get(template_key, "en")
            if entry:
                return entry.subject_template, entry.body_template

        key_tmpl = _TEMPLATES.get(template_key, {})
        if lang in key_tmpl:
            t = key_tmpl[lang]
            return t["subject"], t["body"]

        if "en" in key_tmpl:
            t = key_tmpl["en"]
            return t["subject"], t["body"]

        raise EmailTemplateNotFoundError(
            f"No template found for key={template_key!r}, language={language!r}"
        )

    def render(self, template_key: str, language: str, **kwargs) -> tuple[str, str]:
        """Resolve from DB/fallback then render with _safe() on all values."""
        subject_tmpl, body_tmpl = self.resolve(template_key, language)
        return self.render_raw(subject_tmpl, body_tmpl, **kwargs)

    def render_raw(self, subject_template: str, body_template: str, **kwargs) -> tuple[str, str]:
        """Render arbitrary templates with _safe() applied to all values."""
        safe_kwargs = {k: self._safe(v) for k, v in kwargs.items()}
        subject = subject_template.format(**safe_kwargs)
        body = body_template.format(**safe_kwargs)
        return subject, body

    def validate(
        self,
        template_key: str,
        subject_template: str,
        body_template: str,
    ) -> None:
        """
        Validate a template before saving.
        Raises EmailTemplateValidationError with a descriptive message.
        """
        if template_key not in self.KNOWN_KEYS:
            raise EmailTemplateValidationError(
                f"Unknown template key: {template_key!r}. "
                f"Known keys: {sorted(self.KNOWN_KEYS)}"
            )

        subject_template = (subject_template or "").strip()
        body_template = (body_template or "").strip()

        if not subject_template:
            raise EmailTemplateValidationError("Subject template must not be empty")
        if not body_template:
            raise EmailTemplateValidationError("Body template must not be empty")

        allowed = set(EMAIL_TEMPLATE_VARIABLES.get(template_key, ()))
        for tmpl, label in ((subject_template, "subject"), (body_template, "body")):
            for var in _VAR_RE.findall(tmpl):
                if var not in allowed:
                    raise EmailTemplateValidationError(
                        f"Unknown variable '{{{var}}}' in {label}. "
                        f"Allowed: {sorted(allowed)}"
                    )

        sample = dict(EMAIL_TEMPLATE_SAMPLE_VALUES.get(template_key, {}))
        try:
            self.render_raw(subject_template, body_template, **sample)
        except (KeyError, IndexError) as exc:
            raise EmailTemplateValidationError(
                f"Template render failed with sample values: {exc}"
            ) from exc

    def get_sample_values(self, template_key: str) -> dict:
        return dict(EMAIL_TEMPLATE_SAMPLE_VALUES.get(template_key, {}))

    def list_all(self) -> list[EmailTemplate]:
        return self.repo.list_all()

    def get(self, template_key: str, language: str) -> EmailTemplate | None:
        return self.repo.get(template_key, language)

    def upsert(
        self,
        template_key: str,
        language: str,
        subject_template: str,
        body_template: str,
        updated_by_user_id: str | None = None,
    ) -> EmailTemplate:
        subject_template = (subject_template or "").strip()
        body_template = (body_template or "").strip()
        self.validate(template_key, subject_template, body_template)

        if language not in SUPPORTED_LANGUAGES:
            raise EmailTemplateValidationError(
                f"Unsupported language: {language!r}. Supported: {SUPPORTED_LANGUAGES}"
            )

        now = self._now()
        existing = self.repo.get(template_key, language)
        entry = EmailTemplate(
            id=existing.id if existing else str(uuid.uuid4()),
            template_key=template_key,
            language=language,
            subject_template=subject_template,
            body_template=body_template,
            is_custom=True,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            updated_by_user_id=updated_by_user_id,
        )
        self.repo.upsert(entry)
        return entry

    def reset(self, template_key: str, language: str) -> EmailTemplate:
        """Reset to code fallback content and mark is_custom=False."""
        if template_key not in self.KNOWN_KEYS:
            raise EmailTemplateValidationError(
                f"Unknown template key: {template_key!r}"
            )
        if language not in SUPPORTED_LANGUAGES:
            raise EmailTemplateValidationError(
                f"Unsupported language: {language!r}. Supported: {SUPPORTED_LANGUAGES}"
            )

        key_tmpl = _TEMPLATES.get(template_key, {})
        tmpl = key_tmpl.get(language) or key_tmpl.get("en")
        if not tmpl:
            raise EmailTemplateNotFoundError(
                f"No code fallback for template_key={template_key!r}"
            )

        now = self._now()
        existing = self.repo.get(template_key, language)
        entry = EmailTemplate(
            id=existing.id if existing else str(uuid.uuid4()),
            template_key=template_key,
            language=language,
            subject_template=tmpl["subject"],
            body_template=tmpl["body"],
            is_custom=False,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            updated_by_user_id=None,
        )
        self.repo.upsert(entry)
        return entry
