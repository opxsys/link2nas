from backend.models.job import Job


def filter_jobs_by_status(jobs: list[Job], status: str | None = None) -> list[Job]:
    if not status:
        return jobs

    wanted = str(status).strip().lower()
    return [
        job
        for job in jobs
        if str(job.status or "").strip().lower() == wanted
    ]
