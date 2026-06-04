import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from backend.models.account_token import AccountToken


TOKEN_TYPES = {
    "invitation",
    "password_reset",
    "email_verification",
    "magic_login",
}


class AccountTokenError(Exception):
    pass


class AccountTokenService:
    def __init__(self, token_repo, public_base_url: str | None = None, app_settings_service=None):
        self.token_repo = token_repo
        self._env_public_base_url = (public_base_url or "").rstrip("/")
        self._app_settings_service = app_settings_service

    def _get_public_base_url(self) -> str:
        if self._app_settings_service is not None:
            return self._app_settings_service.get_effective_public_base_url(
                env_fallback=self._env_public_base_url
            )
        return self._env_public_base_url

    def _get_next_base_url(self) -> str:
        """Return the base URL for Next UI deep-links, ensuring exactly one /next suffix."""
        base = self._get_public_base_url().rstrip("/")
        if not base:
            return "/next"
        if base.endswith("/next"):
            return base
        return f"{base}/next"

    def now(self) -> str:
        return datetime.now(UTC).isoformat()

    def hash_token(self, raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def generate_raw_token(self) -> str:
        return "l2nat_" + secrets.token_urlsafe(48)

    def create_token(
        self,
        *,
        user_id: str,
        token_type: str,
        created_by_user_id: str | None,
        ttl_hours: int | None = 24,
        ttl_minutes: int | None = None,
        metadata_json: str = "{}",
    ) -> tuple[AccountToken, str]:
        if token_type not in TOKEN_TYPES:
            raise AccountTokenError("Invalid token type")



        raw_token = self.generate_raw_token()
        timestamp = self.now()

        if ttl_minutes is not None:
            expires_at = (datetime.now(UTC) + timedelta(minutes=int(ttl_minutes))).isoformat()
        else:
            expires_at = (datetime.now(UTC) + timedelta(hours=int(ttl_hours or 24))).isoformat()
            
        self.token_repo.delete_unused_for_user_type(user_id, token_type)

        token = AccountToken(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash=self.hash_token(raw_token),
            token_type=token_type,
            expires_at=expires_at,
            used_at=None,
            created_at=timestamp,
            created_by_user_id=created_by_user_id,
            metadata_json=metadata_json,
        )

        self.token_repo.create(token)

        return token, raw_token

    def get_valid_token(self, raw_token: str, expected_type: str | None = None) -> AccountToken:
        token_hash = self.hash_token(raw_token)
        token = self.token_repo.get_by_hash(token_hash)

        if token is None:
            raise AccountTokenError("Invalid token")

        if expected_type and token.token_type != expected_type:
            raise AccountTokenError("Invalid token type")

        if token.used_at:
            raise AccountTokenError("Token already used")

        expires_at = datetime.fromisoformat(token.expires_at.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        if expires_at <= datetime.now(UTC):
            raise AccountTokenError("Token expired")

        return token

    def consume_token(self, token: AccountToken) -> None:
        self.token_repo.mark_used(token.id, self.now())

    def build_invitation_url(self, raw_token: str) -> str:
        base = self._get_public_base_url()
        if not base:
            return f"/invite?token={raw_token}"
        return f"{base}/invite?token={raw_token}"

    def build_password_reset_url(self, raw_token: str) -> str:
        base = self._get_next_base_url()
        return f"{base}/reset-password?token={raw_token}"

    def build_magic_login_url(self, raw_token: str) -> str:
        base = self._get_next_base_url()
        return f"{base}/magic-login?token={raw_token}"

    def build_email_verification_url(self, raw_token: str) -> str:
        base = self._get_public_base_url()
        if not base:
            return f"/verify-email?token={raw_token}"
        return f"{base}/verify-email?token={raw_token}"
