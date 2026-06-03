from datetime import UTC, datetime

from backend.models.user_integration_settings import UserIntegrationSettings


ALLOWED_PROWLARR_OPEN_MODES = {"iframe", "new_tab", "both"}
ALLOWED_HOME_PAGES = {"jobs", "dashboard", "prowlarr"}


class UserIntegrationSettingsService:
    def __init__(self, repository):
        self.repository = repository

    def now(self) -> str:
        return datetime.now(UTC).isoformat()

    def get_for_user(self, user_id: str) -> UserIntegrationSettings:
        existing = self.repository.get_for_user(user_id)

        if existing:
            return existing

        timestamp = self.now()

        settings = UserIntegrationSettings(
            user_id=user_id,
            prowlarr_enabled=False,
            prowlarr_url="",
            prowlarr_open_mode="both",
            home_page="jobs",
            created_at=timestamp,
            updated_at=timestamp,
        )

        self.repository.upsert(settings)
        return settings

    def update_for_user(self, user_id: str, payload: dict) -> UserIntegrationSettings:
        current = self.get_for_user(user_id)

        prowlarr_enabled = bool(payload.get("prowlarr_enabled", current.prowlarr_enabled))
        prowlarr_url = str(payload.get("prowlarr_url", current.prowlarr_url or "") or "").strip()
        prowlarr_open_mode = str(
            payload.get("prowlarr_open_mode", current.prowlarr_open_mode or "both") or "both"
        ).strip()
        home_page = str(payload.get("home_page", current.home_page or "jobs") or "jobs").strip()

        if prowlarr_open_mode not in ALLOWED_PROWLARR_OPEN_MODES:
            raise ValueError("Invalid prowlarr_open_mode")

        if home_page not in ALLOWED_HOME_PAGES:
            raise ValueError("Invalid home_page")

        if home_page == "prowlarr" and (not prowlarr_enabled or not prowlarr_url):
            home_page = "dashboard"

        timestamp = self.now()

        settings = UserIntegrationSettings(
            user_id=user_id,
            prowlarr_enabled=prowlarr_enabled,
            prowlarr_url=prowlarr_url,
            prowlarr_open_mode=prowlarr_open_mode,
            home_page=home_page,
            created_at=current.created_at or timestamp,
            updated_at=timestamp,
        )

        self.repository.upsert(settings)
        return settings
