from abc import ABC, abstractmethod

from backend.models.announcement import Announcement
from backend.models.announcement_read import AnnouncementRead
from backend.models.destination_config import DestinationConfig
from backend.models.job import Job
from backend.models.provider_config import ProviderConfig
from backend.models.user import User


class UserRepository(ABC):
    @abstractmethod
    def create(self, user: User) -> None: ...

    @abstractmethod
    def get_by_id(self, user_id: str) -> User | None: ...

    @abstractmethod
    def get_by_email(self, email: str) -> User | None: ...

    @abstractmethod
    def list_all(self) -> list[User]: ...

    @abstractmethod
    def update(self, user: User) -> None: ...

    @abstractmethod
    def delete(self, user_id: str) -> None: ...


class JobRepository(ABC):
    @abstractmethod
    def create(self, job: Job) -> None: ...

    @abstractmethod
    def get_by_id(self, user_id: str, job_id: str) -> Job | None: ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[Job]: ...

    @abstractmethod
    def get_existing_by_source(
        self,
        user_id: str,
        source_type: str,
        source_value: str,
        provider_config_id: str | None = None,
        provider_name: str | None = None,
    ) -> Job | None: ...

    @abstractmethod
    def update_provider_state(self, job: Job) -> None: ...

    @abstractmethod
    def update_refresh_state(self, job: Job) -> None: ...

    @abstractmethod
    def update_after_select_files(self, job: Job) -> None: ...

    @abstractmethod
    def update_unrestrict_state(self, job: Job) -> None: ...

    @abstractmethod
    def update_destination_state(self, job: Job) -> None: ...

    @abstractmethod
    def update_full_reset(self, job: Job) -> None: ...

    @abstractmethod
    def update_status_state(self, job: Job) -> None: ...

    @abstractmethod
    def delete(self, user_id: str, job_id: str) -> None: ...


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


class AnnouncementRepository(ABC):
    @abstractmethod
    def create(self, a: Announcement) -> None: ...

    @abstractmethod
    def get_by_id(self, announcement_id: str) -> Announcement | None: ...

    @abstractmethod
    def list_all(self) -> list[Announcement]: ...

    @abstractmethod
    def list_active(self, now: str) -> list[Announcement]: ...

    @abstractmethod
    def update(self, a: Announcement) -> None: ...

    @abstractmethod
    def delete(self, announcement_id: str) -> None: ...


class AnnouncementReadRepository(ABC):
    @abstractmethod
    def upsert(self, r: AnnouncementRead) -> None: ...

    @abstractmethod
    def get(self, announcement_id: str, user_id: str) -> AnnouncementRead | None: ...

    @abstractmethod
    def list_for_announcement(self, announcement_id: str) -> list[AnnouncementRead]: ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[AnnouncementRead]: ...

    @abstractmethod
    def count_stats(self, announcement_id: str) -> dict: ...
