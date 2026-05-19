from dataclasses import dataclass


@dataclass
class EmailTemplate:
    id: str
    template_key: str
    language: str
    subject_template: str
    body_template: str
    is_custom: bool
    created_at: str
    updated_at: str
    updated_by_user_id: str | None = None
