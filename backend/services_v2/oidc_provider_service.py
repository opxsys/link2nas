import json
import re
import uuid

from backend.models.oidc_provider import OidcProvider
from backend.utils.time import utc_now_iso

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_UNSET = object()


# ── Exceptions ────────────────────────────────────────────────────────────────


class OidcProviderError(Exception):
    pass


class OidcProviderValidationError(OidcProviderError):
    pass


class OidcProviderNotFoundError(OidcProviderError):
    pass


class OidcProviderSecretError(OidcProviderError):
    pass


class OidcProviderInUseError(OidcProviderError):
    pass


# ── Service ───────────────────────────────────────────────────────────────────


class OidcProviderService:
    def __init__(self, repo, ext_id_repo, crypto_service):
        self._repo = repo
        self._ext_id_repo = ext_id_repo
        self._crypto = crypto_service

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_admin_dict(self, provider: OidcProvider) -> dict:
        return {
            "id": provider.id,
            "name": provider.name,
            "slug": provider.slug,
            "enabled": provider.enabled,
            "issuer": provider.issuer,
            "client_id": provider.client_id,
            "has_client_secret": bool(provider.encrypted_client_secret),
            "scopes": provider.scopes,
            "button_label": provider.button_label,
            "auto_create_users": provider.auto_create_users,
            "allowed_domains_json": provider.allowed_domains_json,
            "state_ttl_seconds": provider.state_ttl_seconds,
            "exchange_code_ttl_seconds": provider.exchange_code_ttl_seconds,
            "sort_order": provider.sort_order,
            "created_at": provider.created_at,
            "updated_at": provider.updated_at,
        }

    def to_public_dict(self, provider: OidcProvider) -> dict:
        return {"slug": provider.slug, "button_label": provider.button_label}

    # ── Lookups ───────────────────────────────────────────────────────────────

    def list_all(self) -> list[OidcProvider]:
        return self._repo.list_all()

    def list_public_enabled_providers(self, single_user_mode: bool) -> list[dict]:
        if single_user_mode:
            return []
        return [self.to_public_dict(p) for p in self._repo.list_enabled()]

    def get_provider_or_raise(self, provider_id: str) -> OidcProvider:
        p = self._repo.get_by_id(provider_id)
        if p is None:
            raise OidcProviderNotFoundError(f"Provider {provider_id!r} not found")
        return p

    def get_by_slug_or_raise(self, slug: str) -> OidcProvider:
        p = self._repo.get_by_slug(slug)
        if p is None:
            raise OidcProviderNotFoundError(f"Provider slug {slug!r} not found")
        return p

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate_slug(self, slug: str) -> None:
        if not _SLUG_RE.match(slug):
            raise OidcProviderValidationError(
                "Slug must match ^[a-z0-9][a-z0-9_-]{0,63}$"
            )

    def _normalize_issuer(self, issuer: str) -> str:
        return issuer.strip().rstrip("/")

    def _validate_allowed_domains_json(self, value: str) -> None:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise OidcProviderValidationError(
                "allowed_domains_json must be valid JSON"
            ) from exc
        if not isinstance(parsed, list):
            raise OidcProviderValidationError(
                "allowed_domains_json must be a JSON array"
            )

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create_provider(
        self,
        *,
        name: str,
        slug: str,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        scopes: str = "openid email profile",
        button_label: str | None = None,
        enabled: bool = True,
        auto_create_users: bool = False,
        allowed_domains_json: str = "[]",
        state_ttl_seconds: int = 600,
        exchange_code_ttl_seconds: int = 60,
        sort_order: int = 0,
    ) -> OidcProvider:
        self._validate_slug(slug)
        issuer = self._normalize_issuer(issuer)
        if not name.strip():
            raise OidcProviderValidationError("Name cannot be empty")
        if not issuer:
            raise OidcProviderValidationError("issuer cannot be empty")
        if not client_id.strip():
            raise OidcProviderValidationError("client_id cannot be empty")
        self._validate_allowed_domains_json(allowed_domains_json)

        if enabled and not client_secret:
            raise OidcProviderSecretError(
                "client_secret is required when creating an enabled provider"
            )

        encrypted_secret = self._crypto.encrypt(client_secret) if client_secret else None

        now = utc_now_iso()
        provider = OidcProvider(
            id=str(uuid.uuid4()),
            name=name.strip(),
            slug=slug,
            enabled=enabled,
            issuer=issuer,
            client_id=client_id.strip(),
            encrypted_client_secret=encrypted_secret,
            scopes=scopes,
            button_label=(button_label or f"Sign in with {name}").strip(),
            auto_create_users=auto_create_users,
            allowed_domains_json=allowed_domains_json,
            state_ttl_seconds=state_ttl_seconds,
            exchange_code_ttl_seconds=exchange_code_ttl_seconds,
            sort_order=sort_order,
            created_at=now,
            updated_at=now,
        )
        self._repo.create(provider)
        return provider

    def update_provider(
        self,
        provider_id: str,
        *,
        name: str | None = None,
        issuer: str | None = None,
        client_id: str | None = None,
        client_secret=_UNSET,
        scopes: str | None = None,
        button_label: str | None = None,
        enabled: bool | None = None,
        auto_create_users: bool | None = None,
        allowed_domains_json: str | None = None,
        state_ttl_seconds: int | None = None,
        exchange_code_ttl_seconds: int | None = None,
        sort_order: int | None = None,
    ) -> OidcProvider:
        provider = self.get_provider_or_raise(provider_id)

        if name is not None:
            if not name.strip():
                raise OidcProviderValidationError("Name cannot be empty")
            provider.name = name.strip()
        if issuer is not None:
            provider.issuer = self._normalize_issuer(issuer)
        if client_id is not None:
            if not client_id.strip():
                raise OidcProviderValidationError("client_id cannot be empty")
            provider.client_id = client_id.strip()
        if scopes is not None:
            provider.scopes = scopes
        if button_label is not None:
            provider.button_label = button_label.strip()
        if enabled is not None:
            provider.enabled = enabled
        if auto_create_users is not None:
            provider.auto_create_users = auto_create_users
        if allowed_domains_json is not None:
            self._validate_allowed_domains_json(allowed_domains_json)
            provider.allowed_domains_json = allowed_domains_json
        if state_ttl_seconds is not None:
            provider.state_ttl_seconds = state_ttl_seconds
        if exchange_code_ttl_seconds is not None:
            provider.exchange_code_ttl_seconds = exchange_code_ttl_seconds
        if sort_order is not None:
            provider.sort_order = sort_order

        if client_secret is not _UNSET:
            provider.encrypted_client_secret = (
                self._crypto.encrypt(client_secret) if client_secret else None
            )

        provider.updated_at = utc_now_iso()
        self._repo.update(provider)
        return provider

    def delete_provider(self, provider_id: str) -> None:
        provider = self.get_provider_or_raise(provider_id)
        count = self._ext_id_repo.count_by_issuer(provider.issuer)
        if count > 0:
            raise OidcProviderInUseError(
                f"Provider cannot be deleted: {count} user(s) linked via this issuer"
            )
        self._repo.delete(provider_id)
