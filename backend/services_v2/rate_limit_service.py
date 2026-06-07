from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
import time
from typing import Optional

import redis
from flask import current_app, jsonify, request


KNOWN_ANTI_ABUSE_KINDS: list[dict] = [
    {
        "kind": "login",
        "label": "Login",
        "limit_attr": "V2_RATE_LIMIT_LOGIN_MAX",
        "window_attr": "V2_RATE_LIMIT_LOGIN_WINDOW_SECONDS",
    },
    {
        "kind": "magic_login_request",
        "label": "Magic Login Request",
        "limit_attr": "V2_RATE_LIMIT_MAGIC_LOGIN_MAX",
        "window_attr": "V2_RATE_LIMIT_MAGIC_LOGIN_WINDOW_SECONDS",
    },
    {
        "kind": "magic_login_confirm",
        "label": "Magic Login Confirm",
        "limit_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        "window_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    },
    {
        "kind": "password_reset_confirm",
        "label": "Password Reset Confirm",
        "limit_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        "window_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    },
    {
        "kind": "email_verification_confirm",
        "label": "Email Verification Confirm",
        "limit_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        "window_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    },
    {
        "kind": "email_verification_request",
        "label": "Email Verification Request",
        "limit_attr": "V2_RATE_LIMIT_EMAIL_REQUEST_MAX",
        "window_attr": "V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS",
    },
    {
        "kind": "admin_invitation_email",
        "label": "Admin Invitation Email",
        "limit_attr": "V2_RATE_LIMIT_EMAIL_REQUEST_MAX",
        "window_attr": "V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS",
    },
    {
        "kind": "admin_password_reset_email",
        "label": "Admin Password Reset Email",
        "limit_attr": "V2_RATE_LIMIT_EMAIL_REQUEST_MAX",
        "window_attr": "V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS",
    },
    {
        "kind": "qbittorrent_add",
        "label": "qBittorrent Add",
        "limit_attr": "V2_RATE_LIMIT_QBITTORRENT_ADD_MAX",
        "window_attr": "V2_RATE_LIMIT_QBITTORRENT_ADD_WINDOW_SECONDS",
    },
    {
        "kind": "token_status",
        "label": "Token Status",
        "limit_attr": "V2_RATE_LIMIT_TOKEN_STATUS_MAX",
        "window_attr": "V2_RATE_LIMIT_TOKEN_STATUS_WINDOW_SECONDS",
    },
    {
        "kind": "invitation_accept",
        "label": "Invitation Accept",
        "limit_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        "window_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    },
    {
        "kind": "me_password_change",
        "label": "Password Change",
        "limit_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        "window_attr": "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    },
    {
        "kind": "oidc_initiate",
        "label": "OIDC Initiate",
        "limit_attr": "V2_RATE_LIMIT_OIDC_INITIATE_MAX",
        "window_attr": "V2_RATE_LIMIT_OIDC_INITIATE_WINDOW_SECONDS",
        "single_user_hidden": True,
    },
    {
        "kind": "oidc_callback",
        "label": "OIDC Callback",
        "limit_attr": "V2_RATE_LIMIT_OIDC_CALLBACK_MAX",
        "window_attr": "V2_RATE_LIMIT_OIDC_CALLBACK_WINDOW_SECONDS",
        "single_user_hidden": True,
    },
    {
        "kind": "oidc_complete",
        "label": "OIDC Complete",
        "limit_attr": "V2_RATE_LIMIT_OIDC_COMPLETE_MAX",
        "window_attr": "V2_RATE_LIMIT_OIDC_COMPLETE_WINDOW_SECONDS",
        "single_user_hidden": True,
    },
    {
        "kind": "identity_proxy_login",
        "label": "Identity Proxy Login",
        "limit_attr": "V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX",
        "window_attr": "V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_WINDOW_SECONDS",
        "single_user_hidden": True,
    },
]


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int


class MemoryRateLimitBackend:
    def __init__(self) -> None:
        self._lock = Lock()
        self._hits: dict[str, list[datetime]] = {}

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=window_seconds)

        with self._lock:
            hits = [ts for ts in self._hits.get(key, []) if ts > cutoff]

            if len(hits) >= limit:
                oldest = min(hits)
                retry_after = int((oldest + timedelta(seconds=window_seconds) - now).total_seconds())
                retry_after = max(retry_after, 1)
                self._hits[key] = hits
                return RateLimitResult(False, retry_after)

            hits.append(now)
            self._hits[key] = hits
            return RateLimitResult(True, 0)

    def get_snapshot(self, kind: str) -> dict:
        prefix = f"{kind}:"
        with self._lock:
            matching = {k: v for k, v in self._hits.items() if k.startswith(prefix)}
            return {
                "active_identities": len(matching),
                "estimated_hits": sum(len(v) for v in matching.values()),
                "status": "ok",
            }

    def reset_kind(self, kind: str) -> dict:
        prefix = f"{kind}:"
        with self._lock:
            to_remove = [k for k in self._hits if k.startswith(prefix)]
            for k in to_remove:
                del self._hits[k]
            return {"ok": True, "deleted": len(to_remove)}


class RedisRateLimitBackend:
    def __init__(self, redis_url: str, *, key_prefix: str = "link2nas:rate_limit") -> None:
        self.client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=2,
            socket_connect_timeout=2,
        )
        self.key_prefix = key_prefix.strip(":") or "link2nas:rate_limit"

        # Fail fast au démarrage si Redis est configuré mais inaccessible.
        self.client.ping()

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        now_ms = int(time.time() * 1000)
        window_ms = int(window_seconds) * 1000
        cutoff_ms = now_ms - window_ms
        redis_key = f"{self.key_prefix}:{key}"

        pipe = self.client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, cutoff_ms)
        pipe.zcard(redis_key)
        _, current_count = pipe.execute()

        if int(current_count) >= int(limit):
            oldest_items = self.client.zrange(redis_key, 0, 0, withscores=True)

            if oldest_items:
                oldest_ms = int(oldest_items[0][1])
                retry_after = int(((oldest_ms + window_ms) - now_ms) / 1000)
                retry_after = max(retry_after, 1)
            else:
                retry_after = max(int(window_seconds), 1)

            return RateLimitResult(False, retry_after)

        member = f"{now_ms}:{time.monotonic_ns()}"

        pipe = self.client.pipeline()
        pipe.zadd(redis_key, {member: now_ms})
        pipe.expire(redis_key, int(window_seconds) + 60)
        pipe.execute()

        return RateLimitResult(True, 0)

    def get_snapshot(self, kind: str) -> dict:
        pattern = f"{self.key_prefix}:{kind}:*"
        keys: list[str] = []
        cursor = 0
        while True:
            cursor, batch = self.client.scan(cursor, match=pattern, count=100)
            keys.extend(batch)
            if cursor == 0:
                break

        if not keys:
            return {"active_identities": 0, "estimated_hits": 0, "ttl_seconds": None, "status": "ok"}

        pipe = self.client.pipeline()
        for k in keys:
            pipe.zcard(k)
            pipe.ttl(k)
        results = pipe.execute()

        total_hits = 0
        max_ttl = 0
        for i in range(0, len(results), 2):
            total_hits += int(results[i] or 0)
            ttl = int(results[i + 1] or 0)
            if ttl > max_ttl:
                max_ttl = ttl

        return {
            "active_identities": len(keys),
            "estimated_hits": total_hits,
            "ttl_seconds": max_ttl if max_ttl > 0 else None,
            "status": "ok",
        }

    def reset_kind(self, kind: str) -> dict:
        pattern = f"{self.key_prefix}:{kind}:*"
        keys: list[str] = []
        cursor = 0
        while True:
            cursor, batch = self.client.scan(cursor, match=pattern, count=100)
            keys.extend(batch)
            if cursor == 0:
                break

        if keys:
            self.client.delete(*keys)

        return {"ok": True, "deleted": len(keys)}


class RateLimitService:
    def __init__(
        self,
        *,
        enabled: bool = True,
        redis_url: str = "",
        redis_required: bool = False,
    ) -> None:
        self.enabled = bool(enabled)
        self.backend_name = "disabled"

        if not self.enabled:
            self.backend = MemoryRateLimitBackend()
            return

        redis_url = str(redis_url or "").strip()

        if redis_url:
            self.backend = RedisRateLimitBackend(redis_url)
            self.backend_name = "redis"
            return

        if redis_required:
            raise RuntimeError("REDIS_URL is required when V2_RATE_LIMIT_REDIS_REQUIRED=true")

        self.backend = MemoryRateLimitBackend()
        self.backend_name = "memory"

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        if not self.enabled:
            return RateLimitResult(True, 0)

        limit = int(limit)
        window_seconds = int(window_seconds)

        if limit <= 0 or window_seconds <= 0:
            return RateLimitResult(True, 0)

        return self.backend.check(
            key,
            limit=limit,
            window_seconds=window_seconds,
        )

    def get_backend_name(self) -> str:
        return self.backend_name

    def get_key_prefix(self) -> str:
        if isinstance(self.backend, RedisRateLimitBackend):
            return self.backend.key_prefix
        return "link2nas:rate_limit"

    def get_counter_snapshot(self, kind: str) -> dict:
        return self.backend.get_snapshot(kind)

    def reset_kind(self, kind: str) -> dict:
        return self.backend.reset_kind(kind)

    def reset_all_known(self) -> dict:
        results: dict[str, dict] = {}
        for meta in KNOWN_ANTI_ABUSE_KINDS:
            k = meta["kind"]
            try:
                results[k] = self.backend.reset_kind(k)
            except Exception as exc:
                results[k] = {"ok": False, "error": str(exc)}
        return results


def client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip() or "unknown"

    return request.remote_addr or "unknown"


def rate_limit_response(kind: str, identity: str, *, limit_attr: str, window_attr: str):
    settings = current_app.config["SETTINGS"]
    limiter: Optional[RateLimitService] = current_app.config.get("RATE_LIMIT_SERVICE_V2")

    if limiter is None:
        return None

    key = f"{kind}:{client_ip()}:{str(identity or '').strip().lower()}"

    result = limiter.check(
        key,
        limit=int(getattr(settings, limit_attr)),
        window_seconds=int(getattr(settings, window_attr)),
    )

    if result.allowed:
        return None

    response = jsonify({
        "ok": False,
        "error": "too_many_requests",
        "message": "Too many attempts. Please try again later.",
        "retry_after_seconds": result.retry_after_seconds,
    })
    response.status_code = 429
    response.headers["Retry-After"] = str(result.retry_after_seconds)
    return response