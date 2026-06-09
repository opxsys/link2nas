from dataclasses import dataclass

from backend.storage.db import Database
from backend.storage.postgres_db import PostgresDatabase

from backend.repositories.sqlite.user_repository import UserRepository
from backend.repositories.sqlite.job_repository import JobRepository
from backend.repositories.sqlite.provider_config_repository import ProviderConfigRepository
from backend.repositories.sqlite.destination_config_repository import DestinationConfigRepository
from backend.repositories.sqlite.api_token_repository import ApiTokenRepository
from backend.repositories.sqlite.user_api_key_repository import UserApiKeyRepository
from backend.repositories.sqlite.external_client_submission_repository import (
    ExternalClientSubmissionRepository,
)

from backend.repositories.postgres.user_repository import UserRepository as PostgresUserRepository
from backend.repositories.postgres.job_repository import JobRepository as PostgresJobRepository
from backend.repositories.postgres.provider_config_repository import ProviderConfigRepository as PostgresProviderConfigRepository
from backend.repositories.postgres.destination_config_repository import DestinationConfigRepository as PostgresDestinationConfigRepository
from backend.repositories.postgres.api_token_repository import ApiTokenRepository as PostgresApiTokenRepository
from backend.repositories.postgres.user_api_key_repository import UserApiKeyRepository as PostgresUserApiKeyRepository
from backend.repositories.postgres.external_client_submission_repository import (
    ExternalClientSubmissionRepository as PostgresExternalClientSubmissionRepository,
)

from backend.repositories.sqlite.account_token_repository import AccountTokenRepository
from backend.repositories.postgres.account_token_repository import AccountTokenRepository as PostgresAccountTokenRepository

from backend.repositories.sqlite.smtp_settings_repository import SmtpSettingsRepository
from backend.repositories.postgres.smtp_settings_repository import SmtpSettingsRepository as PostgresSmtpSettingsRepository

from backend.repositories.sqlite.app_settings_repository import AppSettingsRepository
from backend.repositories.postgres.app_settings_repository import AppSettingsRepository as PostgresAppSettingsRepository

from backend.repositories.sqlite.notification_config_repository import SQLiteNotificationConfigRepository
from backend.repositories.sqlite.notification_event_repository import SQLiteNotificationEventRepository
from backend.repositories.postgres.notification_config_repository import PostgresNotificationConfigRepository
from backend.repositories.postgres.notification_event_repository import PostgresNotificationEventRepository

from backend.repositories.sqlite.notification_rule_repository import SQLiteNotificationRuleRepository
from backend.repositories.postgres.notification_rule_repository import PostgresNotificationRuleRepository

from backend.repositories.sqlite.user_integration_settings_repository import (
    UserIntegrationSettingsRepository,
)
from backend.repositories.postgres.user_integration_settings_repository import (
    UserIntegrationSettingsRepository as PostgresUserIntegrationSettingsRepository,
)
from backend.repositories.sqlite.announcement_repository import (
    AnnouncementRepository,
)
from backend.repositories.sqlite.announcement_read_repository import (
    AnnouncementReadRepository,
)
from backend.repositories.postgres.announcement_repository import (
    AnnouncementRepository as PostgresAnnouncementRepository,
)
from backend.repositories.postgres.announcement_read_repository import (
    AnnouncementReadRepository as PostgresAnnouncementReadRepository,
)
from backend.repositories.sqlite.email_template_repository import (
    EmailTemplateRepository,
)
from backend.repositories.postgres.email_template_repository import (
    EmailTemplateRepository as PostgresEmailTemplateRepository,
)
from backend.repositories.sqlite.external_identity_repository import (
    ExternalIdentityRepository,
)
from backend.repositories.postgres.external_identity_repository import (
    ExternalIdentityRepository as PostgresExternalIdentityRepository,
)
from backend.repositories.sqlite.oidc_state_repository import (
    OidcStateRepository,
)
from backend.repositories.postgres.oidc_state_repository import (
    OidcStateRepository as PostgresOidcStateRepository,
)
from backend.repositories.sqlite.oidc_provider_repository import (
    OidcProviderRepository,
)
from backend.repositories.postgres.oidc_provider_repository import (
    OidcProviderRepository as PostgresOidcProviderRepository,
)
from backend.repositories.sqlite.identity_proxy_config_repository import (
    IdentityProxyConfigRepository,
)
from backend.repositories.postgres.identity_proxy_config_repository import (
    IdentityProxyConfigRepository as PostgresIdentityProxyConfigRepository,
)
from backend.repositories.sqlite.prowlarr_config_repository import (
    ProwlarrConfigRepository,
)
from backend.repositories.postgres.prowlarr_config_repository import (
    ProwlarrConfigRepository as PostgresProwlarrConfigRepository,
)


class UnsupportedRepositoryBackendError(Exception):
    pass

@dataclass
class Repositories:
    db: object
    user_repository: object
    job_repository: object
    provider_config_repository: object
    destination_config_repository: object
    api_token_repository: object
    user_api_key_repository: object
    user_integration_settings_repository: object
    external_client_submission_repository: object
    account_token_repository: object
    smtp_settings_repository: object
    app_settings_repository: object
    notification_config_repository: object
    notification_event_repository: object
    notification_rule_repository: object
    announcement_repository: object
    announcement_read_repository: object
    email_template_repository: object
    external_identity_repository: object
    oidc_state_repository: object
    oidc_provider_repository: object
    identity_proxy_config_repository: object
    prowlarr_config_repository: object

def build_repositories(settings) -> Repositories:
    backend = settings.V2_DATABASE_BACKEND

    if backend == "sqlite":
        db = Database(str(settings.V2_SQLITE_PATH))
        db.init_schema(str(settings.V2_SCHEMA_PATH))
        db.run_column_migrations()

        return Repositories(
            db=db,
            user_repository=UserRepository(db),
            job_repository=JobRepository(db),
            provider_config_repository=ProviderConfigRepository(db),
            destination_config_repository=DestinationConfigRepository(db),
            api_token_repository=ApiTokenRepository(db),
            user_api_key_repository=UserApiKeyRepository(db),
            user_integration_settings_repository=UserIntegrationSettingsRepository(db),            
            external_client_submission_repository=ExternalClientSubmissionRepository(db),
            account_token_repository=AccountTokenRepository(db),
            smtp_settings_repository=SmtpSettingsRepository(db),
            app_settings_repository=AppSettingsRepository(db),
            notification_config_repository=SQLiteNotificationConfigRepository(db),
            notification_event_repository=SQLiteNotificationEventRepository(db),
            notification_rule_repository=SQLiteNotificationRuleRepository(db),
            announcement_repository=AnnouncementRepository(db),
            announcement_read_repository=AnnouncementReadRepository(db),
            email_template_repository=EmailTemplateRepository(db),
            external_identity_repository=ExternalIdentityRepository(db),
            oidc_state_repository=OidcStateRepository(db),
            oidc_provider_repository=OidcProviderRepository(db),
            identity_proxy_config_repository=IdentityProxyConfigRepository(db),
            prowlarr_config_repository=ProwlarrConfigRepository(db),
        )

    if backend == "postgres":
        db = PostgresDatabase(settings.V2_POSTGRES_DSN)
        db.init_schema(str(settings.V2_POSTGRES_SCHEMA_PATH))

        return Repositories(
            db=db,
            user_repository=PostgresUserRepository(db),
            job_repository=PostgresJobRepository(db),
            provider_config_repository=PostgresProviderConfigRepository(db),
            destination_config_repository=PostgresDestinationConfigRepository(db),
            api_token_repository=PostgresApiTokenRepository(db),
            user_api_key_repository=PostgresUserApiKeyRepository(db),
            user_integration_settings_repository=PostgresUserIntegrationSettingsRepository(db),
            external_client_submission_repository=PostgresExternalClientSubmissionRepository(db),
            account_token_repository=PostgresAccountTokenRepository(db),
            smtp_settings_repository=PostgresSmtpSettingsRepository(db),
            app_settings_repository=PostgresAppSettingsRepository(db),
            notification_config_repository=PostgresNotificationConfigRepository(db),
            notification_event_repository=PostgresNotificationEventRepository(db),
            notification_rule_repository=PostgresNotificationRuleRepository(db),
            announcement_repository=PostgresAnnouncementRepository(db),
            announcement_read_repository=PostgresAnnouncementReadRepository(db),
            email_template_repository=PostgresEmailTemplateRepository(db),
            external_identity_repository=PostgresExternalIdentityRepository(db),
            oidc_state_repository=PostgresOidcStateRepository(db),
            oidc_provider_repository=PostgresOidcProviderRepository(db),
            identity_proxy_config_repository=PostgresIdentityProxyConfigRepository(db),
            prowlarr_config_repository=PostgresProwlarrConfigRepository(db),
        )


    raise UnsupportedRepositoryBackendError(
        f"Unsupported V2_DATABASE_BACKEND: {backend}"
    )
