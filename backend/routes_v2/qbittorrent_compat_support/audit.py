import uuid
from datetime import UTC, datetime

from flask import current_app

from backend.models.external_client_submission import ExternalClientSubmission
from backend.services_v2.user_context import UserContext


def _audit_repo():
    return current_app.config.get("EXTERNAL_CLIENT_SUBMISSION_REPO_V2")


def _create_external_submission_audit(
    *,
    ctx: UserContext,
    input_type: str,
    input_hash: str | None,
    original_name: str | None,
    category: str | None,
) -> str | None:
    repo = _audit_repo()

    if repo is None:
        return None

    timestamp = datetime.now(UTC).isoformat()
    submission_id = str(uuid.uuid4())

    repo.create(
        ExternalClientSubmission(
            id=submission_id,
            user_id=ctx.user_id,
            client_type="qbittorrent_compat",
            source="prowlarr",
            input_type=input_type,
            input_hash=input_hash,
            original_name=original_name,
            category=category,
            provider_config_id=None,
            destination_config_id=None,
            job_id=None,
            status="received",
            error_message=None,
            created_at=timestamp,
            updated_at=timestamp,
        )
    )

    return submission_id


def _update_external_submission_audit(
    submission_id: str | None,
    *,
    job_id: str | None,
    provider_config_id: str | None,
    destination_config_id: str | None,
    status: str,
    error_message: str | None = None,
) -> None:
    if not submission_id:
        return

    repo = _audit_repo()

    if repo is None:
        return

    repo.update_result(
        submission_id,
        job_id=job_id,
        provider_config_id=provider_config_id,
        destination_config_id=destination_config_id,
        status=status,
        error_message=error_message,
        updated_at=datetime.now(UTC).isoformat(),
    )
