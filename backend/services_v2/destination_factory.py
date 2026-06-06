import json
from dataclasses import dataclass

from flask import current_app

from backend.models.destination_config import DestinationConfig
from backend.services_v2.destination_registry import DESTINATION_ALIAS_KEYS, DESTINATION_KEYS
from backend.services_v2.destinations.base import Destination
from backend.services_v2.destinations.links_only_destination import LinksOnlyDestination
from backend.services_v2.destinations.local_destination import LocalDestination
from backend.services_v2.destinations.synology_destination import SynologyDestination


class DestinationConfigNotFoundError(Exception):
    pass


class DestinationConfigDisabledError(Exception):
    pass


class UnknownDestinationError(Exception):
    pass


@dataclass
class ResolvedDestination:
    name: str
    destination: Destination
    config: DestinationConfig | None = None

    @property
    def destination_config_id(self) -> str | None:
        return self.config.id if self.config else None

    @property
    def destination_type(self) -> str | None:
        return self.config.destination_type if self.config else None

    @property
    def destination_profile_name(self) -> str | None:
        return self.config.name if self.config else None


class UserDestinationFactory:
    def __init__(self, destination_config_repository, settings=None):
        self.destination_config_repository = destination_config_repository
        self.settings = settings

    def get_destination_for_user(
        self,
        user_id: str,
        destination_name: str | None = None,
        *,
        destination_config_id: str | None = None,
        allow_links_only: bool = False,
    ) -> Destination:
        resolved = self.resolve_destination_for_user(
            user_id=user_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
            allow_links_only=allow_links_only,
        )
        return resolved.destination

    def resolve_destination_for_user(
        self,
        user_id: str,
        destination_name: str | None = None,
        *,
        destination_config_id: str | None = None,
        allow_links_only: bool = False,
    ) -> ResolvedDestination:
        config = self._resolve_config(
            user_id=user_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
            allow_links_only=allow_links_only,
        )

        if config is None:
            return ResolvedDestination(
                name="links_only",
                destination=LinksOnlyDestination(),
                config=None,
            )

        if not config.is_enabled:
            raise DestinationConfigDisabledError("Destination config is disabled")

        destination_type = DESTINATION_ALIAS_KEYS.get(
            config.destination_type, config.destination_type
        )

        if destination_type == "local":
            try:
                raw_config = json.loads(config.config_json or "{}")
            except json.JSONDecodeError:
                raise UnknownDestinationError("Invalid local destination config")

            base_path = raw_config.get("base_path") or "downloads"

            settings = current_app.config["SETTINGS"]

            return ResolvedDestination(
                name="local",
                destination=LocalDestination(
                    userdata_root=str(settings.USERDATA_DIR),
                    user_id=user_id,
                    base_path=base_path,
                ),
                config=config,
            )

        if destination_type == "synology":
            try:
                cfg = json.loads(config.config_json or "{}")
            except Exception:
                raise UnknownDestinationError("Invalid NAS config")

            crypto = current_app.config["CRYPTO_SERVICE_V2"]

            password = cfg.get("password")
            if password:
                password = crypto.decrypt(password)

            return ResolvedDestination(
                name="synology",
                destination=SynologyDestination(
                    synology_url=cfg["synology_url"],
                    username=cfg["username"],
                    password=password,
                    verify_ssl=cfg.get("verify_ssl", True),
                    destination_base=cfg.get("destination_base"),
                ),
                config=config,
            )

        raise UnknownDestinationError(f"Unknown destination: {destination_type}")

    def resolve_destination_config_for_user(
        self,
        user_id: str,
        destination_name: str | None = None,
        *,
        destination_config_id: str | None = None,
        allow_none: bool = False,
    ) -> DestinationConfig | None:
        return self._resolve_config(
            user_id=user_id,
            destination_name=destination_name,
            destination_config_id=destination_config_id,
            allow_links_only=allow_none,
        )

    def list_enabled_real_destination_names_for_user(self, user_id: str) -> list[str]:
        # Temporary V2 compatibility.
        # Returns destination types, deduplicated.
        configs = self.destination_config_repository.list_for_user(user_id)

        values = []
        for config in configs:
            if config.is_enabled and config.destination_type in DESTINATION_KEYS:
                if config.destination_type not in values:
                    values.append(config.destination_type)

        return values

    def list_enabled_destination_configs_for_user(self, user_id: str) -> list[DestinationConfig]:
        configs = self.destination_config_repository.list_for_user(user_id)

        return [
            config
            for config in configs
            if config.is_enabled
        ]

    def _resolve_config(
        self,
        user_id: str,
        destination_name: str | None = None,
        *,
        destination_config_id: str | None = None,
        allow_links_only: bool = False,
    ) -> DestinationConfig | None:
        if destination_config_id:
            config = self.destination_config_repository.get_by_id(
                user_id,
                destination_config_id,
            )

            if config is None:
                raise DestinationConfigNotFoundError("Destination config not found")

            return config

        if destination_name:
            destination_type = str(destination_name or "").strip().lower()
            destination_type = DESTINATION_ALIAS_KEYS.get(destination_type, destination_type)

            if destination_type == "links_only":
                if allow_links_only:
                    return None
                raise DestinationConfigNotFoundError("links_only is not a real destination profile")

            configs = self.destination_config_repository.list_for_user(user_id)
            enabled_configs = [
                config
                for config in configs
                if config.is_enabled
            ]

            matching_configs = [
                config
                for config in enabled_configs
                if config.destination_type == destination_type
            ]

            if not matching_configs:
                raise DestinationConfigNotFoundError("Destination config not found")

            default_matches = [
                config
                for config in matching_configs
                if config.is_default
            ]

            return default_matches[0] if default_matches else matching_configs[0]

        configs = self.destination_config_repository.list_for_user(user_id)
        enabled_configs = [
            config
            for config in configs
            if config.is_enabled
        ]

        for config in enabled_configs:
            if config.is_default:
                return config

        if len(enabled_configs) == 1:
            return enabled_configs[0]

        if allow_links_only:
            return None

        raise DestinationConfigNotFoundError("No default destination config found")
