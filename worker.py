from __future__ import annotations

from redis import Redis
from rq import Worker, Queue

from config import Settings


def build_redis_connection(settings) -> Redis:
    """Return a Redis connection, preferring REDIS_URL over host/port/db."""
    url = getattr(settings, "REDIS_URL", "") or ""
    if url.strip():
        return Redis.from_url(url, decode_responses=False)
    return Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=False,
    )


def main() -> None:
    settings = Settings()

    redis_conn = build_redis_connection(settings)

    queue = Queue(settings.RQ_QUEUE_NAME, connection=redis_conn)
    worker = Worker([queue], connection=redis_conn)
    worker.work()


if __name__ == "__main__":
    main()
