from abc import ABC, abstractmethod

from backend.models.job import Job


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
