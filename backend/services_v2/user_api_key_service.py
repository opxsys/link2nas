import hashlib
import hmac
import json
import secrets
import uuid
from backend.utils.time import utc_now_iso

from backend.models.user_api_key import UserApiKey


ALLOWED_USER_API_KEY_SCOPES = {
    "jobs:create",
    "jobs:read",
    "qbittorrent:write",
    "extension",
    "scripts",
}


class UserApiKeyValidationError(ValueError):
    pass


now = utc_now_iso


class UserApiKeyService:
    def __init__(self, repository):
        self.repository = repository

    def _hash_key(self, raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def _generate_raw_key(self) -> tuple[str, str]:
        prefix = f"l2n_{secrets.token_hex(4)}"
        secret = secrets.token_urlsafe(32)
        raw_key = f"{prefix}.{secret}"
        return prefix, raw_key

    def _normalize_name(self, name: str) -> str:
        normalized = str(name or "").strip()

        if not normalized:
            raise UserApiKeyValidationError("API key name is required")

        if len(normalized) > 120:
            raise UserApiKeyValidationError("API key name is too long")

        return normalized

    def _normalize_scopes(self, scopes) -> list[str]:
        if scopes is None:
            return []

        if not isinstance(scopes, list):
            raise UserApiKeyValidationError("scopes must be a list")

        normalized = []

        for scope in scopes:
            value = str(scope or "").strip()

            if not value:
                continue

            if value not in ALLOWED_USER_API_KEY_SCOPES:
                raise UserApiKeyValidationError(f"Unsupported API key scope: {value}")

            if value not in normalized:
                normalized.append(value)

        return normalized

    def serialize(self, api_key: UserApiKey) -> dict:
        scopes = []

        try:
            scopes = json.loads(api_key.scopes_json or "[]")
        except Exception:
            scopes = []

        return {
            "id": api_key.id,
            "name": api_key.name,
            "key_prefix": api_key.key_prefix,
            "scopes": scopes,
            "is_active": bool(api_key.is_active),
            "revoked_at": api_key.revoked_at,
            "last_used_at": api_key.last_used_at,
            "last_used_ip": api_key.last_used_ip,
            "last_used_scope": api_key.last_used_scope,
            "created_at": api_key.created_at,
            "updated_at": api_key.updated_at,
        }

    def list_for_user(self, user_id: str) -> list[dict]:
        return [
            self.serialize(api_key)
            for api_key in self.repository.list_for_user(user_id)
        ]

    def create_for_user(self, user_id: str, name: str, scopes=None) -> dict:
        clean_name = self._normalize_name(name)
        clean_scopes = self._normalize_scopes(scopes)

        timestamp = now()
        key_prefix, raw_key = self._generate_raw_key()
        key_hash = self._hash_key(raw_key)

        api_key = UserApiKey(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name=clean_name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            scopes_json=json.dumps(clean_scopes),
            is_active=True,
            revoked_at=None,
            last_used_at=None,
            last_used_ip=None,
            last_used_scope=None,
            created_at=timestamp,
            updated_at=timestamp,
        )

        saved = self.repository.create(api_key)
        payload = self.serialize(saved)

        # Important: raw key returned only at creation time.
        payload["key"] = raw_key

        return payload

    def revoke_for_user(self, user_id: str, key_id: str) -> dict:
        timestamp = now()
        ok = self.repository.revoke(user_id, key_id, timestamp)

        if not ok:
            raise UserApiKeyValidationError("API key not found")

        api_key = self.repository.get_for_user(user_id, key_id)
        if not api_key:
            return {"ok": True}

        return self.serialize(api_key)

    def delete_for_user(self, user_id: str, key_id: str) -> bool:
        return self.repository.delete(user_id, key_id)

    def verify_external_key(self, raw_key: str, required_scope: str | None = None):
        """
        Prévu pour la future API qBittorrent compatibility / Prowlarr.

        Ne pas brancher sur get_user_context() maintenant.
        Les clés utilisateur externes ne doivent pas donner accès à toute l'UI/API web.
        """
        value = str(raw_key or "").strip()

        if "." not in value:
            return None

        key_prefix = value.split(".", 1)[0]
        api_key = self.repository.get_active_by_prefix(key_prefix)

        if not api_key:
            return None

        candidate_hash = self._hash_key(value)

        if not hmac.compare_digest(candidate_hash, api_key.key_hash):
            return None

        try:
            scopes = json.loads(api_key.scopes_json or "[]")
        except Exception:
            scopes = []

        if required_scope and required_scope not in scopes:
            return None

        self.repository.mark_used(
            key_id=api_key.id,
            used_at=now(),
            scope=required_scope,
        )

        return api_key
