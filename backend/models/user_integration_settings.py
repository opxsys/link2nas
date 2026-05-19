from dataclasses import dataclass


@dataclass
class UserIntegrationSettings:
    user_id: str

    prowlarr_enabled: bool = False
    prowlarr_url: str | None = None
    prowlarr_open_mode: str = "both"
    home_page: str = "jobs"

    created_at: str | None = None
    updated_at: str | None = None
