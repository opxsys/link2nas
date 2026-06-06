from dataclasses import dataclass

from flask import current_app

from backend.models.provider_config import ProviderConfig
from backend.services_v2.provider_registry import build_provider
from backend.services_v2.providers.base import Provider


class ProviderConfigNotFoundError(Exception):
    pass


class ProviderConfigDisabledError(Exception):
    pass


class UnknownProviderError(Exception):
    pass


@dataclass
class ResolvedProvider:
    config: ProviderConfig
    provider: Provider

    @property
    def provider_config_id(self) -> str:
        return self.config.id

    @property
    def provider_type(self) -> str:
        return self.config.provider_type

    @property
    def provider_name(self) -> str:
        # Temporary V2 compatibility alias.
        return self.config.provider_type

    @property
    def provider_profile_name(self) -> str:
        return self.config.name


class UserProviderFactory:
    def __init__(self, settings, provider_config_repository):
        self.settings = settings
        self.provider_config_repository = provider_config_repository

    def get_provider_for_user(
        self,
        user_id: str,
        provider_name: str | None = None,
        *,
        provider_config_id: str | None = None,
    ) -> Provider:
        resolved = self.resolve_provider_for_user(
            user_id=user_id,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
        )
        return resolved.provider

    def resolve_provider_for_user(
        self,
        user_id: str,
        provider_name: str | None = None,
        *,
        provider_config_id: str | None = None,
    ) -> ResolvedProvider:
        config = self._resolve_config(
            user_id=user_id,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
        )

        if not config.is_enabled:
            raise ProviderConfigDisabledError("Provider config is disabled")

        crypto = current_app.config["CRYPTO_SERVICE_V2"]
        token = crypto.decrypt(config.encrypted_api_key)

        if not token:
            raise ProviderConfigNotFoundError("Provider API key is missing")

        provider_type = config.provider_type

        try:
            provider = build_provider(provider_type, token, self.settings)
        except ValueError as exc:
            raise UnknownProviderError(str(exc)) from exc

        # Keep legacy attribute expected by existing provider/job code.
        provider.provider_name = provider_type

        # Extra metadata for V3-aware callers.
        provider.provider_config_id = config.id
        provider.provider_profile_name = config.name

        return ResolvedProvider(
            config=config,
            provider=provider,
        )

    def resolve_provider_name_for_user(
        self,
        user_id: str,
        provider_name: str | None = None,
        *,
        provider_config_id: str | None = None,
    ) -> str:
        config = self._resolve_config(
            user_id=user_id,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
        )

        if not config.is_enabled:
            raise ProviderConfigDisabledError("Provider config is disabled")

        return config.provider_type

    def resolve_provider_config_for_user(
        self,
        user_id: str,
        provider_name: str | None = None,
        *,
        provider_config_id: str | None = None,
    ) -> ProviderConfig:
        config = self._resolve_config(
            user_id=user_id,
            provider_name=provider_name,
            provider_config_id=provider_config_id,
        )

        if not config.is_enabled:
            raise ProviderConfigDisabledError("Provider config is disabled")

        return config

    def list_enabled_provider_names_for_user(self, user_id: str) -> list[str]:
        # Temporary V2 compatibility.
        # Returns provider types, deduplicated.
        configs = self.provider_config_repository.list_for_user(user_id)

        values = []
        for config in configs:
            if config.is_enabled and config.provider_type not in values:
                values.append(config.provider_type)

        return values

    def list_enabled_provider_configs_for_user(self, user_id: str) -> list[ProviderConfig]:
        configs = self.provider_config_repository.list_for_user(user_id)

        return [
            config
            for config in configs
            if config.is_enabled
        ]

    def _resolve_config(
        self,
        user_id: str,
        provider_name: str | None = None,
        *,
        provider_config_id: str | None = None,
    ) -> ProviderConfig:
        if provider_config_id:
            config = self.provider_config_repository.get_by_id(
                user_id,
                provider_config_id,
            )

            if config is None:
                raise ProviderConfigNotFoundError("Provider config not found")

            return config

        configs = self.provider_config_repository.list_for_user(user_id)

        enabled_configs = [
            config
            for config in configs
            if config.is_enabled
        ]

        if provider_name:
            provider_type = str(provider_name or "").strip().lower()

            matching_configs = [
                config
                for config in enabled_configs
                if config.provider_type == provider_type
            ]

            if not matching_configs:
                raise ProviderConfigNotFoundError("Provider config not found")

            default_matches = [
                config
                for config in matching_configs
                if config.is_default
            ]

            return default_matches[0] if default_matches else matching_configs[0]

        for config in enabled_configs:
            if config.is_default:
                return config

        if len(enabled_configs) == 1:
            return enabled_configs[0]

        raise ProviderConfigNotFoundError("No default provider config found")
