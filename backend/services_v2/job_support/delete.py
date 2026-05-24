from backend.models.job import Job
from backend.services_v2.user_context import UserContext


def delete_job_impl(
    service,
    context: UserContext,
    job_id: str,
) -> bool:
    job = service.get_job(context, job_id)

    if job is None:
        return False

    try:
        service._delete_provider_resources_best_effort(context, job)
    except Exception:
        pass

    service.job_repository.delete(context.user_id, job_id)
    return True
