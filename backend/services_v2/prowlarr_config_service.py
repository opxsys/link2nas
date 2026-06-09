import uuid
from dataclasses import dataclass

from backend.models.prowlarr_config import ProwlarrConfig
from backend.utils.time import utc_now_iso


class ProwlarrConfigError(Exception):
    pass


@dataclass
class EffectiveConfig:
    config: ProwlarrConfig | None
    source: str  # 'user' | 'global' | 'none'

    @property
    def available(self) -> bool:
        return self.config is not None


class ProwlarrConfigService:
    def __init__(self, repository, crypto_service):
        self.repo = repository
        self.crypto = crypto_service

    # ── read ────────────────────────────────────────────────────────────────────

    def get_global_config(self) -> ProwlarrConfig | None:
        return self.repo.get_global()

    def get_user_config(self, user_id: str) -> ProwlarrConfig | None:
        return self.repo.get_for_user(user_id)

    def resolve_effective_config(self, user_id: str) -> EffectiveConfig:
        """
        Priority:
          1. user config — enabled, non-empty base_url, and has encrypted_api_key
          2. global config — enabled, non-empty base_url, and has encrypted_api_key
          3. none
        """
        user_cfg = self.repo.get_for_user(user_id)
        if user_cfg and user_cfg.enabled and user_cfg.base_url and user_cfg.encrypted_api_key:
            return EffectiveConfig(config=user_cfg, source="user")

        global_cfg = self.repo.get_global()
        if global_cfg and global_cfg.enabled and global_cfg.base_url and global_cfg.encrypted_api_key:
            return EffectiveConfig(config=global_cfg, source="global")

        return EffectiveConfig(config=None, source="none")

    # ── write ───────────────────────────────────────────────────────────────────

    def save_global_config(
        self,
        *,
        enabled: bool,
        base_url: str | None,
        api_key: str | None,
        label: str | None = None,
    ) -> ProwlarrConfig:
        existing = self.repo.get_global()
        self._validate(enabled=enabled, base_url=base_url, api_key=api_key, existing=existing)
        return self._save(
            scope="global",
            user_id=None,
            enabled=enabled,
            base_url=base_url,
            api_key=api_key,
            label=label,
            existing=existing,
        )

    def save_user_config(
        self,
        *,
        user_id: str,
        enabled: bool,
        base_url: str | None,
        api_key: str | None,
    ) -> ProwlarrConfig:
        existing = self.repo.get_for_user(user_id)
        self._validate(enabled=enabled, base_url=base_url, api_key=api_key, existing=existing)
        return self._save(
            scope="user",
            user_id=user_id,
            enabled=enabled,
            base_url=base_url,
            api_key=api_key,
            label=None,
            existing=existing,
        )

    def delete_global_config(self) -> None:
        self.repo.delete_global()

    def delete_user_config(self, user_id: str) -> None:
        self.repo.delete_for_user(user_id)

    # ── serialization ───────────────────────────────────────────────────────────

    def to_safe_dict(self, config: ProwlarrConfig | None) -> dict | None:
        """Never includes api_key. Exposes has_api_key only."""
        if config is None:
            return None
        return {
            "enabled": config.enabled,
            "base_url": config.base_url or "",
            "has_api_key": bool(config.encrypted_api_key),
            "label": config.label,
            "tested_at": config.tested_at,
            "last_test_status": config.last_test_status,
            "last_test_message": config.last_test_message,
            "created_at": config.created_at,
            "updated_at": config.updated_at,
        }

    def get_decrypted_api_key(self, config: ProwlarrConfig) -> str | None:
        """For internal use only — never expose the result in API responses."""
        if not config.encrypted_api_key:
            return None
        return self.crypto.decrypt(config.encrypted_api_key)

    # ── internal ────────────────────────────────────────────────────────────────

    def _validate(
        self,
        *,
        enabled: bool,
        base_url: str | None,
        api_key: str | None,
        existing: ProwlarrConfig | None,
    ) -> None:
        # None or whitespace-only api_key means "keep existing" — not an error.
        api_key_new = str(api_key).strip() if api_key is not None else ""
        base_url_clean = str(base_url or "").strip()
        existing_key = existing.encrypted_api_key if existing else None

        if enabled:
            if not base_url_clean:
                raise ProwlarrConfigError("base_url is required when enabled")
            if not api_key_new and not existing_key:
                raise ProwlarrConfigError("api_key is required when enabled")

    def _save(
        self,
        *,
        scope: str,
        user_id: str | None,
        enabled: bool,
        base_url: str | None,
        api_key: str | None,
        label: str | None,
        existing: ProwlarrConfig | None,
    ) -> ProwlarrConfig:
        now = utc_now_iso()
        config_id = existing.id if existing else str(uuid.uuid4())
        created_at = existing.created_at if existing else now

        api_key_clean = str(api_key).strip() if api_key is not None else None
        if api_key_clean:
            encrypted_key = self.crypto.encrypt(api_key_clean)
        else:
            encrypted_key = existing.encrypted_api_key if existing else None

        config = ProwlarrConfig(
            id=config_id,
            scope=scope,
            user_id=user_id,
            enabled=enabled,
            base_url=str(base_url or "").strip() or None,
            encrypted_api_key=encrypted_key,
            label=label,
            tested_at=existing.tested_at if existing else None,
            last_test_status=existing.last_test_status if existing else None,
            last_test_message=existing.last_test_message if existing else None,
            created_at=created_at,
            updated_at=now,
        )

        self.repo.upsert(config)
        return config
