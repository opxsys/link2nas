from __future__ import annotations

from rq import Worker, Queue

from config import Settings
from backend.services_v2.redis_connection import build_redis_connection


def main() -> None:
    settings = Settings()

    redis_conn = build_redis_connection(settings, decode_responses=False)

    queue = Queue(settings.RQ_QUEUE_NAME, connection=redis_conn)
    worker = Worker([queue], connection=redis_conn)
    worker.work()


if __name__ == "__main__":
    main()
