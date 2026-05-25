import json
import logging

from backend.utils.time import utc_now_iso as now

logger = logging.getLogger(__name__)

_USABLE_STATUSES = frozenset({"ready", "partially_ready", "completed"})


def _classify_exception(exc: Exception) -> tuple[str, dict, str]:
    """
    Classify a destination exception into (message_key, params, short_label).

    Returns a user-friendly i18n key and a short single-line label.
    The raw exception is NOT included in the returned values to avoid
    leaking technical stack details into the UI.
    """
    msg = str(exc).lower()

    if "connection refused" in msg:
        return "destination.message.connection_refused", {}, "Connection refused"

    if "timed out" in msg or "timeout" in msg:
        return "destination.message.timeout", {}, "Connection timed out"

    if "auth" in msg:
        return "destination.message.auth_failed", {}, "Authentication failed"

    # Generic fallback — first line only, capped at 120 chars
    first_line = str(exc).split("\n")[0][:120].strip()
    return "destination.message.failed", {"reason": first_line}, first_line


def apply_destination_failure(job, exc: Exception) -> None:
    """
    Mark the destination as failed with i18n-friendly fields.

    - Sets destination_status, destination_message, destination_message_key,
      destination_message_params, destination_last_attempt, updated_at.
    - Does NOT touch job.error_message when the job is already in a usable
      state (ready / partially_ready / completed): the job is still usable,
      only the destination send failed.
    - Logs the full exception for technical debugging.
    """
    logger.warning(
        "Destination send failed for job %s: %s",
        getattr(job, "id", None),
        exc,
    )

    message_key, params, short_label = _classify_exception(exc)

    job.destination_status = "failed"
    job.destination_message = short_label
    job.destination_message_key = message_key
    job.destination_message_params = json.dumps(params) if params else None
    job.destination_last_attempt = now()
    job.updated_at = now()

    job_status = str(getattr(job, "status", "") or "").strip().lower()
    if job_status not in _USABLE_STATUSES:
        job.error_message = str(exc)
