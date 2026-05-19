import json
import uuid
from backend.utils.time import utc_now_iso

from flask import current_app

from backend.models.destination_config import DestinationConfig
from backend.services_v2.user_context import UserContext


now = utc_now_iso


def normalize_destination_type(value: str | None) -> str:
    destination_type = str(value or "").strip().lower()

    if destination_type == "nas":
        destination_type = "synology"

    if destination_type not in {"synology", "local"}:
        raise ValueError("Unsupported destination type")

    return destination_type


class DestinationConfigService:
    def __init__(self, destination_config_repository):
        self.destination_config_repository = destination_config_repository

    def save_destination_config(
        self,
        context: UserContext,
        destination_name: str | None = None,
        config_json: str = "{}",
        is_enabled: bool = True,
        is_default: bool = False,
        *,
        destination_type: str | None = None,
        name: str | None = None,
        destination_config_id: str | None = None,
    ) -> DestinationConfig:
        """
        V3 profile-aware save.

        Temporary compatibility:
        - old callers may still pass destination_name="synology" or "local"
        - new callers should pass destination_type="synology", name="NAS maison"
        """

        resolved_destination_type = normalize_destination_type(
            destination_type or destination_name
        )

        resolved_name = str(name or "").strip()

        if not resolved_name:
            # Compatibility default. This keeps old frontend/routes usable during the refactor.
            resolved_name = (
                "NAS Synology"
                if resolved_destination_type == "synology"
                else "Local"
            )

        existing = None

        if destination_config_id:
            existing = self.destination_config_repository.get_by_id(
                context.user_id,
                destination_config_id,
            )

            if existing is None:
                raise ValueError("Destination profile not found")
        else:
            existing = self.destination_config_repository.get_by_name(
                context.user_id,
                resolved_name,
            )

            # Temporary fallback for old V2 callers.
            if existing is None and destination_name and not name:
                existing = self.destination_config_repository.get(
                    context.user_id,
                    destination_name,
                )

        cfg = json.loads(config_json or "{}")

        if resolved_destination_type == "synology":
            crypto = current_app.config["CRYPTO_SERVICE_V2"]

            if cfg.get("password"):
                cfg["password"] = crypto.encrypt(cfg["password"])
            elif existing:
                old = json.loads(existing.config_json or "{}")
                if old.get("password"):
                    cfg["password"] = old["password"]

            config_json = json.dumps(cfg)

        # Rule 4: setting as default implicitly enables it.
        if is_default:
            is_enabled = True

        # Rule 7: disabling the default destination.
        if existing and existing.is_default and not is_enabled:
            all_destinations = self.destination_config_repository.list_for_user(context.user_id)
            other_active = [d for d in all_destinations if d.id != existing.id and d.is_enabled]
            if other_active:
                raise ValueError(
                    "Cannot disable the default destination while other active destinations exist. "
                    "Set another default destination first."
                )
            is_default = False

        # Rule 5: removing the default flag while the destination stays enabled.
        elif existing and existing.is_default and not is_default:
            raise ValueError(
                "Cannot remove default flag from the default destination. "
                "Set another default destination first."
            )

        # Rules 3 / 10: auto-promote when no default exists.
        if not is_default and is_enabled:
            current_default = self.destination_config_repository.get_default(context.user_id)
            if current_default is None:
                is_default = True

        config = DestinationConfig(
            id=existing.id if existing else str(uuid.uuid4()),
            user_id=context.user_id,
            destination_type=resolved_destination_type,
            name=resolved_name,
            is_enabled=is_enabled,
            is_default=is_default,
            config_json=config_json,
            created_at=existing.created_at if existing else now(),
            updated_at=now(),
        )

        self.destination_config_repository.upsert(config)

        refreshed = self.destination_config_repository.get_by_id(
            context.user_id,
            config.id,
        )

        return refreshed or config

    def delete_destination_config(
        self,
        context: UserContext,
        destination_config_id: str,
    ) -> None:
        config = self.destination_config_repository.get_by_id(
            context.user_id,
            destination_config_id,
        )

        if config is None:
            raise ValueError("Destination profile not found")

        # Rule 9: cannot delete the default destination if other active destinations exist.
        if config.is_default:
            all_destinations = self.destination_config_repository.list_for_user(context.user_id)
            other_active = [d for d in all_destinations if d.id != config.id and d.is_enabled]
            if other_active:
                raise ValueError(
                    "Cannot delete the default destination while other active destinations exist. "
                    "Set another default destination first."
                )

        self.destination_config_repository.delete(context.user_id, destination_config_id)

    def get_destination_config(
        self,
        context: UserContext,
        destination_name: str | None = None,
        *,
        destination_config_id: str | None = None,
        name: str | None = None,
    ) -> DestinationConfig | None:
        if destination_config_id:
            return self.destination_config_repository.get_by_id(
                context.user_id,
                destination_config_id,
            )

        if name:
            return self.destination_config_repository.get_by_name(
                context.user_id,
                name,
            )

        if destination_name:
            return self.destination_config_repository.get(
                context.user_id,
                destination_name,
            )

        return self.destination_config_repository.get_default(context.user_id)

    def get_default_destination_config(
        self,
        context: UserContext,
    ) -> DestinationConfig | None:
        return self.destination_config_repository.get_default(context.user_id)

    def list_destination_configs(
        self,
        context: UserContext,
    ) -> list[DestinationConfig]:
        return self.destination_config_repository.list_for_user(context.user_id)
