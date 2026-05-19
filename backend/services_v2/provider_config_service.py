import uuid
from backend.utils.time import utc_now_iso

from flask import current_app

from backend.models.provider_config import ProviderConfig
from backend.services_v2.user_context import UserContext


now = utc_now_iso


def normalize_provider_type(value: str | None) -> str:
    provider_type = str(value or "").strip().lower()

    if provider_type not in {"realdebrid", "alldebrid"}:
        raise ValueError("Unsupported provider type")

    return provider_type


class ProviderConfigService:
    def __init__(self, provider_config_repository):
        self.provider_config_repository = provider_config_repository

    def save_provider_config(
        self,
        context: UserContext,
        provider_name: str | None = None,
        encrypted_api_key: str | None = None,
        is_enabled: bool = True,
        is_default: bool = False,
        account_expires_at: str | None = None,
        *,
        provider_type: str | None = None,
        name: str | None = None,
        provider_config_id: str | None = None,
    ) -> ProviderConfig:
        """
        V3 profile-aware save.

        Temporary compatibility:
        - old callers may still pass provider_name="realdebrid"
        - new callers should pass provider_type="realdebrid", name="RealDebrid perso"
        """

        resolved_provider_type = normalize_provider_type(provider_type or provider_name)
        resolved_name = str(name or "").strip()

        if not resolved_name:
            # Compatibility default. This keeps old frontend/routes usable during the refactor.
            resolved_name = (
                "RealDebrid"
                if resolved_provider_type == "realdebrid"
                else "AllDebrid"
            )

        crypto = current_app.config["CRYPTO_SERVICE_V2"]

        existing = None

        if provider_config_id:
            existing = self.provider_config_repository.get_by_id(
                context.user_id,
                provider_config_id,
            )

            if existing is None:
                raise ValueError("Provider profile not found")
        else:
            existing = self.provider_config_repository.get_by_name(
                context.user_id,
                resolved_name,
            )

            # Temporary fallback for old V2 callers.
            if existing is None and provider_name and not name:
                existing = self.provider_config_repository.get(
                    context.user_id,
                    provider_name,
                )

        if encrypted_api_key is None:
            if existing:
                encrypted_api_key = existing.encrypted_api_key
        elif str(encrypted_api_key).strip():
            encrypted_api_key = crypto.encrypt(encrypted_api_key)
        elif existing:
            encrypted_api_key = existing.encrypted_api_key
        else:
            encrypted_api_key = None

        # UX rule:
        # setting a provider as default implicitly enables it.
        if is_default:
            is_enabled = True

        if existing and existing.is_default and not is_enabled:
            all_providers = self.provider_config_repository.list_for_user(context.user_id)
            other_active = [p for p in all_providers if p.id != existing.id and p.is_enabled]
            if other_active:
                raise ValueError(
                    "Cannot disable the default provider while other active providers exist. "
                    "Set another default provider first."
                )
            is_default = False

        elif existing and existing.is_default and not is_default:
            raise ValueError(
                "Cannot remove default flag from the default provider. Set another default provider first."
            )

        if not is_default and is_enabled:
            current_default = self.provider_config_repository.get_default(context.user_id)
            if current_default is None:
                is_default = True

        config = ProviderConfig(
            id=existing.id if existing else str(uuid.uuid4()),
            user_id=context.user_id,
            provider_type=resolved_provider_type,
            name=resolved_name,
            is_enabled=is_enabled,
            is_default=is_default,
            encrypted_api_key=encrypted_api_key,
            account_expires_at=account_expires_at,
            created_at=existing.created_at if existing else now(),
            updated_at=now(),
        )

        self.provider_config_repository.upsert(config)
        return config

    def get_provider_config(
        self,
        context: UserContext,
        provider_name: str | None = None,
        *,
        provider_config_id: str | None = None,
        name: str | None = None,
    ) -> ProviderConfig | None:
        if provider_config_id:
            return self.provider_config_repository.get_by_id(
                context.user_id,
                provider_config_id,
            )

        if name:
            return self.provider_config_repository.get_by_name(
                context.user_id,
                name,
            )

        if provider_name:
            return self.provider_config_repository.get(
                context.user_id,
                provider_name,
            )

        return self.provider_config_repository.get_default(context.user_id)

    def get_default_provider_config(
        self,
        context: UserContext,
    ) -> ProviderConfig | None:
        return self.provider_config_repository.get_default(context.user_id)

    def list_provider_configs(
        self,
        context: UserContext,
    ) -> list[ProviderConfig]:
        return self.provider_config_repository.list_for_user(context.user_id)

    def delete_provider_config(
        self,
        context: UserContext,
        provider_config_id: str,
    ) -> None:
        config = self.provider_config_repository.get_by_id(
            context.user_id,
            provider_config_id,
        )

        if config is None:
            raise ValueError("Provider profile not found")

        if config.is_default:
            all_providers = self.provider_config_repository.list_for_user(context.user_id)
            other_active = [p for p in all_providers if p.id != config.id and p.is_enabled]
            if other_active:
                raise ValueError(
                    "Cannot delete the default provider while other active providers exist. "
                    "Set another default provider first."
                )

        self.provider_config_repository.delete(context.user_id, provider_config_id)

    def update_account_expires_at(
        self,
        context: UserContext,
        provider_name: str | None = None,
        account_expires_at: str | None = None,
        *,
        provider_config_id: str | None = None,
    ) -> None:
        config = None

        if provider_config_id:
            config = self.provider_config_repository.get_by_id(
                context.user_id,
                provider_config_id,
            )
        elif provider_name:
            config = self.provider_config_repository.get(
                context.user_id,
                provider_name,
            )

        if config is None:
            raise ValueError("Provider profile not found")

        self.provider_config_repository.update_account_expires_at(
            user_id=context.user_id,
            config_id=config.id,
            account_expires_at=account_expires_at,
            updated_at=now(),
        )
