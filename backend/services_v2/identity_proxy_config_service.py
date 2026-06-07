import json
import uuid

from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.services_v2.identity_proxy_validators import SUPPORTED_PROVIDER_TYPES
from backend.services_v2.identity_proxy_validators.base import IdentityProxyConfigError
from backend.utils.time import utc_now_iso

_DEFAULT_LABELS: dict[str, str] = {
    "cloudflare_access": "Continue with Cloudflare Access",
}


# ── Provider-specific config_json validators ──────────────────────────────────


def _normalize_team_domain(raw: str) -> str:
    domain = raw.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/")


def _validate_cloudflare_access(cfg: dict) -> dict:
    team_domain = cfg.get("team_domain", "").strip()
    audience = cfg.get("audience", "").strip()
    if not team_domain:
        raise IdentityProxyConfigError(
            "config_json.team_domain is required for cloudflare_access"
        )
    if not audience:
        raise IdentityProxyConfigError(
            "config_json.audience is required for cloudflare_access"
        )
    cfg["team_domain"] = _normalize_team_domain(team_domain)
    return cfg


_PROVIDER_CONFIG_VALIDATORS = {
    "cloudflare_access": _validate_cloudflare_access,
}


# ── JSON helpers ──────────────────────────────────────────────────────────────


def _validate_config_json(provider_type: str, raw: str) -> str:
    try:
        cfg = json.loads(raw)
    except Exception:
        raise IdentityProxyConfigError("config_json must be valid JSON")
    if not isinstance(cfg, dict):
        raise IdentityProxyConfigError("config_json must be a JSON object")
    validator = _PROVIDER_CONFIG_VALIDATORS.get(provider_type)
    if validator:
        cfg = validator(cfg)
    return json.dumps(cfg)


def _validate_allowed_domains_json(raw: str) -> str:
    try:
        domains = json.loads(raw)
    except Exception:
        raise IdentityProxyConfigError("allowed_domains_json must be valid JSON")
    if not isinstance(domains, list):
        raise IdentityProxyConfigError("allowed_domains_json must be a JSON array")
    for item in domains:
        if not isinstance(item, str):
            raise IdentityProxyConfigError(
                "allowed_domains_json must be an array of strings"
            )
    return json.dumps(domains)


# ── Service ───────────────────────────────────────────────────────────────────


class IdentityProxyConfigService:
    def __init__(self, config_repo):
        self._repo = config_repo

    def create_config(
        self,
        *,
        name: str,
        provider_type: str,
        label: str | None = None,
        enabled: bool = False,
        auto_login: bool = False,
        auto_create_users: bool = False,
        allowed_domains_json: str = "[]",
        config_json: str = "{}",
    ) -> IdentityProxyConfig:
        name = (name or "").strip()
        if not name:
            raise IdentityProxyConfigError("name is required")

        provider_type = (provider_type or "").strip()
        if not provider_type:
            raise IdentityProxyConfigError("provider_type is required")
        if provider_type not in SUPPORTED_PROVIDER_TYPES:
            raise IdentityProxyConfigError(
                f"Unsupported provider_type: {provider_type!r}. "
                f"Supported: {SUPPORTED_PROVIDER_TYPES}"
            )

        if not label or not label.strip():
            label = _DEFAULT_LABELS.get(provider_type, "Sign in")

        config_json = _validate_config_json(provider_type, config_json)
        allowed_domains_json = _validate_allowed_domains_json(allowed_domains_json)

        now = utc_now_iso()
        config = IdentityProxyConfig(
            id=str(uuid.uuid4()),
            name=name,
            provider_type=provider_type,
            enabled=enabled,
            label=label,
            auto_login=auto_login,
            auto_create_users=auto_create_users,
            allowed_domains_json=allowed_domains_json,
            config_json=config_json,
            created_at=now,
            updated_at=now,
        )
        self._repo.create(config)
        return config

    def update_config(
        self,
        config_id: str,
        *,
        name: str | None = None,
        label: str | None = None,
        enabled: bool | None = None,
        auto_login: bool | None = None,
        auto_create_users: bool | None = None,
        allowed_domains_json: str | None = None,
        config_json: str | None = None,
    ) -> IdentityProxyConfig:
        config = self.get_config_or_raise(config_id)

        if name is not None:
            name = name.strip()
            if not name:
                raise IdentityProxyConfigError("name cannot be empty")
            config.name = name

        if label is not None:
            config.label = (
                label.strip() or _DEFAULT_LABELS.get(config.provider_type, "Sign in")
            )

        if enabled is not None:
            config.enabled = enabled
        if auto_login is not None:
            config.auto_login = auto_login
        if auto_create_users is not None:
            config.auto_create_users = auto_create_users

        if allowed_domains_json is not None:
            config.allowed_domains_json = _validate_allowed_domains_json(
                allowed_domains_json
            )

        if config_json is not None:
            config.config_json = _validate_config_json(config.provider_type, config_json)

        config.updated_at = utc_now_iso()
        self._repo.update(config)
        return config

    def get_config_or_raise(self, config_id: str) -> IdentityProxyConfig:
        config = self._repo.get_by_id(config_id)
        if config is None:
            raise IdentityProxyConfigError(
                f"Identity proxy config not found: {config_id!r}"
            )
        return config

    def get_first_config(self) -> IdentityProxyConfig | None:
        return self._repo.get_first()

    def list_configs(self) -> list[IdentityProxyConfig]:
        return self._repo.list_all()

    def delete_config(self, config_id: str) -> None:
        self.get_config_or_raise(config_id)
        self._repo.delete(config_id)

    def to_admin_dict(self, config: IdentityProxyConfig) -> dict:
        return {
            "id": config.id,
            "name": config.name,
            "provider_type": config.provider_type,
            "enabled": config.enabled,
            "label": config.label,
            "auto_login": config.auto_login,
            "auto_create_users": config.auto_create_users,
            "allowed_domains_json": config.allowed_domains_json,
            "config_json": config.config_json,
            "created_at": config.created_at,
            "updated_at": config.updated_at,
        }

    def get_public_status(self) -> dict:
        config = self._repo.get_first()
        if config is None or not config.enabled:
            return {"enabled": False}
        return {
            "enabled": True,
            "provider_type": config.provider_type,
            "label": config.label,
            "auto_login": config.auto_login,
        }
