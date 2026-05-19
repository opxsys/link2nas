from abc import ABC, abstractmethod

from backend.models.api_token import ApiToken


class ApiTokenRepository(ABC):
    @abstractmethod
    def create(self, token: ApiToken) -> None: ...

    @abstractmethod
    def get_active_by_token(self, token: str) -> ApiToken | None: ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[ApiToken]: ...

    @abstractmethod
    def deactivate(self, user_id: str, token_id: str) -> None: ...
