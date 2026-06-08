from rq import Queue

from backend.models.job import Job
from backend.services_v2.redis_connection import build_redis_connection
from backend.services_v2.user_context import UserContext


def enqueue_local_download(
    settings,
    context: UserContext,
    job: Job,
    destination_config_id: str | None,
) -> None:
    redis_conn = build_redis_connection(settings, decode_responses=False)

    queue = Queue(
        settings.RQ_LOCAL_DOWNLOAD_QUEUE_NAME,
        connection=redis_conn,
    )

    queue.enqueue(
        "backend.services_v2.local_download_worker.perform_local_download_job",
        context.user_id,
        job.id,
        destination_config_id,
        job_timeout="24h",
        result_ttl=3600,
        failure_ttl=86400,
    )
