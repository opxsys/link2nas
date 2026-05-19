from dataclasses import dataclass


@dataclass
class ExternalClientSubmission:
    id: str
    user_id: str

    client_type: str
    source: str

    input_type: str
    input_hash: str | None
    original_name: str | None
    category: str | None

    provider_config_id: str | None
    destination_config_id: str | None
    job_id: str | None

    status: str
    error_message: str | None

    created_at: str
    updated_at: str
