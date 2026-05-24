from backend.models.job import Job
from backend.services_v2.job_support.status_actions import ACTION_RULES


def get_allowed_actions(job: Job) -> list[str]:
    return ACTION_RULES.get(job.status, [])


def ensure_action_allowed(job: Job, action: str) -> None:
    allowed = get_allowed_actions(job)

    if action not in allowed:
        raise ValueError(
            f"Action '{action}' is not allowed from status '{job.status}'"
        )
