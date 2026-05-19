from __future__ import annotations

from redis import Redis
from rq import Worker, Queue

from config import Settings


def main() -> None:
    settings = Settings()

    redis_conn = Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=False,
    )

    queue = Queue(settings.RQ_QUEUE_NAME, connection=redis_conn)
    worker = Worker([queue], connection=redis_conn)
    worker.work()


if __name__ == "__main__":
    main()