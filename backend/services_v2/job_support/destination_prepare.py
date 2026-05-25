import json

from backend.utils.time import utc_now_iso as now
from backend.models.job import Job
from backend.services_v2.user_context import UserContext


def prepare_destination_send(
    service,
    context: UserContext,
    job: "Job",
    destination_name: "str | None",
    destination_config_id: "str | None",
) -> "tuple[object, list[dict]]":
    output_links = json.loads(job.output_links_json or "[]")

    if not isinstance(output_links, list) or not output_links:
        raise ValueError("Invalid output links")

    if service.destination_factory is None:
        raise RuntimeError("Destination factory is not configured")

    resolved = service.destination_factory.resolve_destination_for_user(
        user_id=context.user_id,
        destination_config_id=destination_config_id or job.destination_config_id,
        destination_name=destination_name if destination_config_id is None else None,
    )

    job.destination_config_id = resolved.destination_config_id
    job.destination_name = resolved.name
    job.destination_profile_name = resolved.destination_profile_name
    job.send_to_destination = True
    job.destination_message_key = None
    job.destination_message_params = None
    job.destination_last_attempt = now()
    job.updated_at = now()

    if resolved.name != "local":
        job.destination_status = "sending"
        job.destination_message = "Sending to destination"
        job.destination_message_key = "destination.message.sending"
        job.destination_message_params = None
        job.destination_progress = 0
        job.sent_to_destination = False
        job.sent_to_destination_at = None
        job.error_message = None
        service.job_repository.update_destination_state(job)

    return resolved, output_links
