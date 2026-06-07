import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import jwt
import requests as _http
from jwt import PyJWKClient

from backend.models.api_token import ApiToken
from backend.models.external_identity import ExternalIdentity
from backend.models.oidc_provider import OidcProvider
from backend.models.oidc_state import OidcState
from backend.models.user import User
from backend.utils.time import utc_now_iso

_now = utc_now_iso


# ── Exceptions ────────────────────────────────────────────────────────────────


class OidcError(Exception):
    pass


class OidcDisabledError(OidcError):
    pass


class OidcConfigError(OidcError):
    pass


class OidcStateError(OidcError):
    pass


class OidcTokenError(OidcError):
    pass


class OidcUserError(OidcError):
    pass


class OidcExchangeError(OidcError):
    pass


# ── Service ───────────────────────────────────────────────────────────────────


class OidcService:
    def __init__(
        self,
        settings,
        user_repo,
        external_identity_repo,
        oidc_state_repo,
        api_token_repo,
        oidc_provider_repo,
        crypto_service,
    ):
        self._settings = settings
        self._user_repo = user_repo
        self._ext_id_repo = external_identity_repo
        self._oidc_state_repo = oidc_state_repo
        self._token_repo = api_token_repo
        self._provider_repo = oidc_provider_repo
        self._crypto = crypto_service

    # ── Guards ────────────────────────────────────────────────────────────────

    def _check_enabled(self) -> None:
        if getattr(self._settings, "LINK2NAS_SINGLE_USER_MODE", False):
            raise OidcDisabledError("OIDC is not available in single-user mode")

    # ── Random value generation ───────────────────────────────────────────────

    def generate_state(self) -> str:
        return secrets.token_urlsafe(32)

    def generate_nonce(self) -> str:
        return secrets.token_urlsafe(32)

    def generate_exchange_code(self) -> str:
        return secrets.token_urlsafe(32)

    # ── Provider metadata ─────────────────────────────────────────────────────

    def fetch_provider_metadata(self, issuer: str) -> dict:
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        try:
            resp = _http.get(url, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise OidcConfigError(
                f"Cannot reach OIDC provider metadata: {type(exc).__name__}"
            ) from exc

    # ── Authorization URL ─────────────────────────────────────────────────────

    def _callback_uri(self, provider_slug: str) -> str:
        base = getattr(self._settings, "PUBLIC_BASE_URL", "").rstrip("/")
        return base + f"/api/v2/auth/oidc/{provider_slug}/callback"

    def build_authorization_url(
        self, metadata: dict, state: str, nonce: str, provider: OidcProvider
    ) -> str:
        endpoint = metadata.get("authorization_endpoint")
        if not endpoint:
            raise OidcConfigError("Provider metadata missing authorization_endpoint")
        params = {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": self._callback_uri(provider.slug),
            "scope": provider.scopes,
            "state": state,
            "nonce": nonce,
        }
        return endpoint + "?" + urlencode(params)

    # ── Token exchange ────────────────────────────────────────────────────────

    def exchange_authorization_code(
        self,
        metadata: dict,
        authorization_code: str,
        client_id: str,
        client_secret: str,
        provider_slug: str,
    ) -> dict:
        token_endpoint = metadata.get("token_endpoint")
        if not token_endpoint:
            raise OidcConfigError("Provider metadata missing token_endpoint")
        try:
            resp = _http.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": authorization_code,
                    "redirect_uri": self._callback_uri(provider_slug),
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise OidcTokenError(f"Token exchange failed: {type(exc).__name__}") from exc

    # ── id_token validation ───────────────────────────────────────────────────

    def validate_id_token(
        self,
        id_token: str,
        metadata: dict,
        nonce: str,
        client_id: str,
        issuer: str,
    ) -> dict:
        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise OidcConfigError("Provider metadata missing jwks_uri")

        try:
            jwks_client = PyJWKClient(jwks_uri)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        except Exception as exc:
            raise OidcTokenError(f"JWKS key resolution failed: {type(exc).__name__}") from exc

        try:
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "ES256", "RS384", "ES384", "RS512"],
                audience=client_id,
                issuer=issuer,
                options={"require": ["sub", "iss", "aud", "exp", "iat"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise OidcTokenError("id_token expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise OidcTokenError("id_token audience mismatch") from exc
        except jwt.InvalidIssuerError as exc:
            raise OidcTokenError("id_token issuer mismatch") from exc
        except jwt.DecodeError as exc:
            raise OidcTokenError("id_token decode error") from exc
        except Exception as exc:
            raise OidcTokenError(f"id_token validation failed: {type(exc).__name__}") from exc

        if claims.get("nonce") != nonce:
            raise OidcTokenError("id_token nonce mismatch")

        email_verified = claims.get("email_verified", False)
        if isinstance(email_verified, str):
            email_verified = email_verified.lower() == "true"
        if not email_verified:
            raise OidcUserError("email_verified is not true")

        email = claims.get("email", "").strip().lower()
        if not email:
            raise OidcUserError("id_token missing email claim")

        claims["email"] = email
        return claims

    # ── Account checks ────────────────────────────────────────────────────────

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
            raise OidcUserError("User account is disabled")
        if self._is_account_expired(user):
            raise OidcUserError("User account has expired")

    # ── User mapping ──────────────────────────────────────────────────────────

    def resolve_or_create_user(
        self, claims: dict, provider: OidcProvider
    ) -> tuple[User, ExternalIdentity]:
        issuer = claims["iss"]
        subject = claims["sub"]
        email = claims["email"]
        now = _now()

        # Step 1: existing external identity
        identity = self._ext_id_repo.get_by_issuer_subject(issuer, subject)
        if identity is not None:
            user = self._user_repo.get_by_id(identity.user_id)
            if user is None:
                raise OidcUserError("Linked user not found")
            self._reject_if_ineligible(user)
            self._ext_id_repo.update_last_used(identity.id, now)
            return user, identity

        # Step 2: existing local user by verified email
        user = self._user_repo.get_by_email(email)
        if user is not None:
            self._reject_if_ineligible(user)
            identity = ExternalIdentity(
                id=str(uuid.uuid4()),
                user_id=user.id,
                provider="oidc",
                issuer=issuer,
                subject=subject,
                email=email,
                linked_at=now,
                last_used_at=now,
            )
            self._ext_id_repo.create(identity)
            return user, identity

        # Step 3: auto-create if allowed
        if not provider.auto_create_users:
            raise OidcUserError("No matching user and auto-create is disabled")

        try:
            allowed_domains: set = set(json.loads(provider.allowed_domains_json or "[]"))
        except Exception:
            allowed_domains = set()
        if allowed_domains:
            domain = email.split("@")[-1] if "@" in email else ""
            if domain not in allowed_domains:
                raise OidcUserError("Email domain is not allowed")

        display_name = (claims.get("name") or claims.get("given_name") or "").strip() or None
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            display_name=display_name,
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
            provider="oidc",
            issuer=issuer,
            subject=subject,
            email=email,
            linked_at=now,
            last_used_at=now,
        )
        self._ext_id_repo.create(identity)
        return user, identity

    # ── api_token creation ────────────────────────────────────────────────────

    def create_api_token(self, user_id: str) -> ApiToken:
        now = _now()
        token = ApiToken(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token="l2n_" + secrets.token_urlsafe(32),
            label="oidc login token",
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        self._token_repo.create(token)
        return token

    # ── Initiate ──────────────────────────────────────────────────────────────

    def initiate(self, provider_slug: str) -> tuple[str, str]:
        """Looks up provider by slug, stores state+nonce in DB. Returns (auth_url, state)."""
        self._check_enabled()

        provider = self._provider_repo.get_by_slug(provider_slug)
        if provider is None:
            raise OidcConfigError(f"Unknown OIDC provider: {provider_slug!r}")
        if not provider.enabled:
            raise OidcDisabledError(f"OIDC provider {provider_slug!r} is disabled")

        self._oidc_state_repo.delete_expired(_now())

        state = self.generate_state()
        nonce = self.generate_nonce()
        now = _now()
        expires_at = (
            datetime.now(UTC) + timedelta(seconds=provider.state_ttl_seconds)
        ).isoformat()

        self._oidc_state_repo.create(OidcState(
            id=str(uuid.uuid4()),
            state=state,
            nonce=nonce,
            created_at=now,
            expires_at=expires_at,
            provider_id=provider.id,
        ))

        metadata = self.fetch_provider_metadata(provider.issuer)
        return self.build_authorization_url(metadata, state, nonce, provider), state

    # ── Callback ──────────────────────────────────────────────────────────────

    def handle_callback(
        self, provider_slug: str, state_param: str, authorization_code: str
    ) -> str:
        """Validates OIDC response, resolves user. Returns exchange_code."""
        self._check_enabled()

        provider = self._provider_repo.get_by_slug(provider_slug)
        if provider is None:
            raise OidcConfigError(f"Unknown OIDC provider: {provider_slug!r}")
        if not provider.enabled:
            raise OidcDisabledError(f"OIDC provider {provider_slug!r} is disabled")

        oidc_state = self._oidc_state_repo.get_valid_by_state(state_param, _now())
        if oidc_state is None:
            raise OidcStateError("Invalid, expired, or already used state")
        if oidc_state.provider_id != provider.id:
            raise OidcStateError("State does not belong to this provider")

        if not provider.encrypted_client_secret:
            raise OidcConfigError("OIDC provider has no client_secret configured")
        try:
            client_secret = self._crypto.decrypt(provider.encrypted_client_secret)
        except Exception as exc:
            raise OidcConfigError("OIDC provider client_secret could not be decrypted") from exc
        if not client_secret:
            raise OidcConfigError("OIDC provider has no client_secret configured")

        metadata = self.fetch_provider_metadata(provider.issuer)
        token_response = self.exchange_authorization_code(
            metadata, authorization_code, provider.client_id, client_secret, provider_slug
        )

        id_token_str = token_response.get("id_token")
        if not id_token_str:
            raise OidcTokenError("No id_token in provider response")

        claims = self.validate_id_token(
            id_token_str, metadata, oidc_state.nonce, provider.client_id, provider.issuer
        )
        user, _identity = self.resolve_or_create_user(claims, provider)

        exchange_code = self.generate_exchange_code()
        exchange_expires_at = (
            datetime.now(UTC) + timedelta(seconds=provider.exchange_code_ttl_seconds)
        ).isoformat()

        self._oidc_state_repo.mark_callback_consumed(
            state_id=oidc_state.id,
            exchange_code=exchange_code,
            user_id=user.id,
            expires_at=exchange_expires_at,
            consumed_at=_now(),
        )
        return exchange_code

    # ── Complete ──────────────────────────────────────────────────────────────

    def complete_login(self, exchange_code: str) -> tuple[str, User]:
        """Consumes exchange_code, re-validates user, creates api_token. One-time use."""
        oidc_state = self._oidc_state_repo.get_valid_by_exchange_code(exchange_code, _now())
        if oidc_state is None:
            raise OidcExchangeError("Invalid or expired exchange code")

        user = self._user_repo.get_by_id(oidc_state.user_id)
        if user is None:
            raise OidcUserError("User not found")
        self._reject_if_ineligible(user)

        api_token = self.create_api_token(user.id)
        self._oidc_state_repo.delete(oidc_state.id)

        return api_token.token, user
