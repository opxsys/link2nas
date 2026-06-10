from abc import ABC, abstractmethod

from backend.models.announcement import Announcement
from backend.models.announcement_read import AnnouncementRead
from backend.models.destination_config import DestinationConfig
from backend.models.external_identity import ExternalIdentity
from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.models.job import Job
from backend.models.oidc_provider import OidcProvider
from backend.models.oidc_state import OidcState
from backend.models.provider_config import ProviderConfig
from backend.models.prowlarr_config import ProwlarrConfig
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


class ExternalIdentityRepository(ABC):
    @abstractmethod
    def get_by_issuer_subject(self, issuer: str, subject: str) -> ExternalIdentity | None: ...

    @abstractmethod
    def get_by_user_id(self, user_id: str) -> list[ExternalIdentity]: ...

    @abstractmethod
    def create(self, identity: ExternalIdentity) -> None: ...

    @abstractmethod
    def update_last_used(self, identity_id: str, last_used_at: str) -> None: ...

    @abstractmethod
    def count_by_issuer(self, issuer: str) -> int: ...


class OidcStateRepository(ABC):
    @abstractmethod
    def create(self, state: OidcState) -> None: ...

    @abstractmethod
    def get_valid_by_state(self, state: str, now_iso: str) -> OidcState | None: ...

    @abstractmethod
    def mark_callback_consumed(
        self,
        state_id: str,
        exchange_code: str,
        user_id: str,
        expires_at: str,
        consumed_at: str,
    ) -> None: ...

    @abstractmethod
    def get_valid_by_exchange_code(self, exchange_code: str, now_iso: str) -> OidcState | None: ...

    @abstractmethod
    def delete(self, state_id: str) -> None: ...

    @abstractmethod
    def delete_expired(self, now_iso: str) -> None: ...


class OidcProviderRepository(ABC):
    @abstractmethod
    def create(self, provider: OidcProvider) -> None: ...

    @abstractmethod
    def get_by_id(self, provider_id: str) -> OidcProvider | None: ...

    @abstractmethod
    def get_by_slug(self, slug: str) -> OidcProvider | None: ...

    @abstractmethod
    def get_by_issuer(self, issuer: str) -> OidcProvider | None: ...

    @abstractmethod
    def list_all(self) -> list[OidcProvider]: ...

    @abstractmethod
    def list_enabled(self) -> list[OidcProvider]: ...

    @abstractmethod
    def update(self, provider: OidcProvider) -> None: ...

    @abstractmethod
    def delete(self, provider_id: str) -> None: ...


class IdentityProxyConfigRepository(ABC):
    @abstractmethod
    def create(self, config: IdentityProxyConfig) -> None: ...

    @abstractmethod
    def get_by_id(self, config_id: str) -> IdentityProxyConfig | None: ...

    @abstractmethod
    def get_first(self) -> IdentityProxyConfig | None: ...

    @abstractmethod
    def list_all(self) -> list[IdentityProxyConfig]: ...

    @abstractmethod
    def update(self, config: IdentityProxyConfig) -> None: ...

    @abstractmethod
    def delete(self, config_id: str) -> None: ...


class ProwlarrConfigRepository(ABC):
    @abstractmethod
    def get_global(self) -> ProwlarrConfig | None: ...

    @abstractmethod
    def get_for_user(self, user_id: str) -> ProwlarrConfig | None: ...

    @abstractmethod
    def upsert(self, config: ProwlarrConfig) -> None: ...

    @abstractmethod
    def delete_global(self) -> None: ...

    @abstractmethod
    def delete_for_user(self, user_id: str) -> None: ...
