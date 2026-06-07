import json
import secrets
import uuid
from datetime import UTC, datetime

from backend.models.api_token import ApiToken
from backend.models.external_identity import ExternalIdentity
from backend.models.user import User
from backend.services_v2.identity_proxy_validators import get_identity_proxy_validator
from backend.services_v2.identity_proxy_validators.base import (
    IdentityProxyDisabledError,
    IdentityProxyUserError,
)
from backend.utils.time import utc_now_iso

_now = utc_now_iso


class IdentityProxyAuthService:
    def __init__(
        self,
        settings,
        config_repo,
        user_repo,
        external_identity_repo,
        api_token_repo,
    ):
        self._settings = settings
        self._config_repo = config_repo
        self._user_repo = user_repo
        self._ext_id_repo = external_identity_repo
        self._token_repo = api_token_repo

    # ── Public status ─────────────────────────────────────────────────────────

    def get_effective_config(self):
        config = self._config_repo.get_first()
        if config is None or not config.enabled:
            return None
        return config

    def get_public_status(self, single_user_mode: bool) -> dict:
        if single_user_mode:
            return {"enabled": False}
        config = self.get_effective_config()
        if config is None:
            return {"enabled": False}
        return {
            "enabled": True,
            "provider_type": config.provider_type,
            "label": config.label,
            "auto_login": config.auto_login,
        }

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self, headers: dict) -> tuple[str, User]:
        if getattr(self._settings, "LINK2NAS_SINGLE_USER_MODE", False):
            raise IdentityProxyDisabledError(
                "Identity Proxy is not available in single-user mode"
            )

        config = self.get_effective_config()
        if config is None:
            raise IdentityProxyDisabledError(
                "Identity Proxy is not configured or disabled"
            )

        validator = get_identity_proxy_validator(config.provider_type)
        claims = validator.validate_request(headers, config)

        self._check_allowed_domain(claims.email, config.allowed_domains_json)

        user = self._resolve_or_create_user(claims, config)
        api_token = self._create_api_token(user.id)
        return api_token.token, user

    # ── Domain check ──────────────────────────────────────────────────────────

    def _check_allowed_domain(self, email: str, allowed_domains_json: str) -> None:
        try:
            allowed: list = json.loads(allowed_domains_json or "[]")
        except Exception:
            allowed = []
        if not allowed:
            return
        domain = email.split("@")[-1] if "@" in email else ""
        if domain not in allowed:
            raise IdentityProxyUserError("Email domain is not allowed")

    # ── Account guards ────────────────────────────────────────────────────────

    def _is_account_expired(self, user: User) -> bool:
        raw = getattr(user, "account_expires_at", None)
        if not raw:
            return False
        try:
            expires_at = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at <= datetime.now(UTC)

    def _reject_if_ineligible(self, user: User) -> None:
        if not user.is_active:
            raise IdentityProxyUserError("User account is disabled")
        if self._is_account_expired(user):
            raise IdentityProxyUserError("User account has expired")

    # ── User resolution ───────────────────────────────────────────────────────

    def _resolve_or_create_user(self, claims, config) -> User:
        now = _now()
        issuer = claims.issuer
        subject = claims.subject
        email = claims.email

        # Step 1: existing external identity
        identity = self._ext_id_repo.get_by_issuer_subject(issuer, subject)
        if identity is not None:
            user = self._user_repo.get_by_id(identity.user_id)
            if user is None:
                raise IdentityProxyUserError("Linked user not found")
            self._reject_if_ineligible(user)
            self._ext_id_repo.update_last_used(identity.id, now)
            return user

        # Step 2: existing user by email
        user = self._user_repo.get_by_email(email)
        if user is not None:
            self._reject_if_ineligible(user)
            identity = ExternalIdentity(
                id=str(uuid.uuid4()),
                user_id=user.id,
                provider="identity_proxy",
                issuer=issuer,
                subject=subject,
                email=email,
                linked_at=now,
                last_used_at=now,
            )
            self._ext_id_repo.create(identity)
            return user

        # Step 3: auto-create
        if not config.auto_create_users:
            raise IdentityProxyUserError("No matching user and auto-create is disabled")

        user = User(
            id=str(uuid.uuid4()),
            email=email,
            display_name=claims.display_name,
            role="user",
            is_active=True,
            created_at=now,
            updated_at=now,
            email_verified_at=now,
        )
        self._user_repo.create(user)

        identity = ExternalIdentity(
            id=str(uuid.uuid4()),
            user_id=user.id,
            provider="identity_proxy",
            issuer=issuer,
            subject=subject,
            email=email,
            linked_at=now,
            last_used_at=now,
        )
        self._ext_id_repo.create(identity)
        return user

    # ── Token creation ────────────────────────────────────────────────────────

    def _create_api_token(self, user_id: str) -> ApiToken:
        now = _now()
        token = ApiToken(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token="l2n_" + secrets.token_urlsafe(32),
            label="identity proxy login token",
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        self._token_repo.create(token)
        return token
