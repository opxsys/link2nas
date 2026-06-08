from __future__ import annotations

from redis import Redis


def build_redis_connection(settings, *, decode_responses: bool = False) -> Redis:
    """Return a Redis connection, preferring REDIS_URL over host/port/db."""
    url = getattr(settings, "REDIS_URL", "") or ""
    if url.strip():
        return Redis.from_url(url, decode_responses=decode_responses)
    return Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=decode_responses,
    )
