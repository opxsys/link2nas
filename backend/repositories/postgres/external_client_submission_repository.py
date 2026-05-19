from backend.models.external_client_submission import ExternalClientSubmission


class ExternalClientSubmissionRepository:
    def __init__(self, db):
        self.db = db

    def _row_to_submission(self, row) -> ExternalClientSubmission:
        return ExternalClientSubmission(
            id=row["id"],
            user_id=row["user_id"],
            client_type=row["client_type"],
            source=row["source"],
            input_type=row["input_type"],
            input_hash=row["input_hash"],
            original_name=row["original_name"],
            category=row["category"],
            provider_config_id=row["provider_config_id"],
            destination_config_id=row["destination_config_id"],
            job_id=row["job_id"],
            status=row["status"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def create(self, submission: ExternalClientSubmission) -> ExternalClientSubmission:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO external_client_submissions (
                        id,
                        user_id,
                        client_type,
                        source,
                        input_type,
                        input_hash,
                        original_name,
                        category,
                        provider_config_id,
                        destination_config_id,
                        job_id,
                        status,
                        error_message,
                        created_at,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        submission.id,
                        submission.user_id,
                        submission.client_type,
                        submission.source,
                        submission.input_type,
                        submission.input_hash,
                        submission.original_name,
                        submission.category,
                        submission.provider_config_id,
                        submission.destination_config_id,
                        submission.job_id,
                        submission.status,
                        submission.error_message,
                        submission.created_at,
                        submission.updated_at,
                    ),
                )
            conn.commit()

        return submission

    def update_result(
        self,
        submission_id: str,
        *,
        job_id: str | None,
        provider_config_id: str | None,
        destination_config_id: str | None,
        status: str,
        error_message: str | None,
        updated_at: str,
    ) -> None:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE external_client_submissions
                    SET
                        job_id = %s,
                        provider_config_id = %s,
                        destination_config_id = %s,
                        status = %s,
                        error_message = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (
                        job_id,
                        provider_config_id,
                        destination_config_id,
                        status,
                        error_message,
                        updated_at,
                        submission_id,
                    ),
                )
            conn.commit()

    def list_for_user(self, user_id: str, limit: int = 50) -> list[ExternalClientSubmission]:
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM external_client_submissions
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (user_id, int(limit)),
                )
                rows = cur.fetchall()

        return [self._row_to_submission(row) for row in rows]
