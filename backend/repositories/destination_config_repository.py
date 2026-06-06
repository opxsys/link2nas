from abc import ABC, abstractmethod

from backend.models.destination_config import DestinationConfig


class DestinationConfigRepository(ABC):
    @abstractmethod
    def upsert(self, config: DestinationConfig) -> None: ...

    @abstractmethod
    def get_by_id(self, user_id: str, config_id: str) -> DestinationConfig | None: ...

    @abstractmethod
    def get_by_name(self, user_id: str, name: str) -> DestinationConfig | None: ...

    @abstractmethod
    def get_default(self, user_id: str) -> DestinationConfig | None: ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[DestinationConfig]: ...

    @abstractmethod
    def delete(self, user_id: str, config_id: str) -> None: ...

    # Temporary V2 compatibility helper.
    # Resolves by technical destination type only when it is unambiguous.
    def get(self, user_id: str, destination_name: str) -> DestinationConfig | None:
        destination_type = str(destination_name or "").strip().lower()
        from backend.services_v2.destination_registry import DESTINATION_ALIAS_KEYS

        destination_type = DESTINATION_ALIAS_KEYS.get(destination_type, destination_type)

        matches = [
            item
            for item in self.list_for_user(user_id)
            if item.destination_type == destination_type
        ]

        if not matches:
            return None

        default_matches = [item for item in matches if item.is_default]
        return default_matches[0] if default_matches else matches[0]

    def delete_by_destination_name(self, user_id: str, destination_name: str) -> None:
        config = self.get(user_id, destination_name)
        if config:
            self.delete(user_id, config.id)
