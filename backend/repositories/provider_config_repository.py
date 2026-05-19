from abc import ABC, abstractmethod

from backend.models.provider_config import ProviderConfig


class ProviderConfigRepository(ABC):
    @abstractmethod
    def upsert(self, config: ProviderConfig) -> None: ...

    @abstractmethod
    def get_by_id(self, user_id: str, config_id: str) -> ProviderConfig | None: ...

    @abstractmethod
    def get_by_name(self, user_id: str, name: str) -> ProviderConfig | None: ...

    @abstractmethod
    def get_default(self, user_id: str) -> ProviderConfig | None: ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[ProviderConfig]: ...

    @abstractmethod
    def update_account_expires_at(
        self,
        user_id: str,
        config_id: str,
        account_expires_at: str | None,
        updated_at: str,
    ) -> None: ...

    @abstractmethod
    def delete(self, user_id: str, config_id: str) -> None: ...

    # Temporary V2 compatibility helpers.
    # These resolve by technical provider type only when it is unambiguous.
    def get(self, user_id: str, provider_name: str) -> ProviderConfig | None:
        provider_type = str(provider_name or "").strip().lower()
        matches = [
            item
            for item in self.list_for_user(user_id)
            if item.provider_type == provider_type
        ]

        if not matches:
            return None

        default_matches = [item for item in matches if item.is_default]
        return default_matches[0] if default_matches else matches[0]

    def delete_by_provider_name(self, user_id: str, provider_name: str) -> None:
        config = self.get(user_id, provider_name)
        if config:
            self.delete(user_id, config.id)
