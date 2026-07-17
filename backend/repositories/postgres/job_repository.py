from backend.models.job import Job


class JobRepository:
    def __init__(self, db):
        self.db = db

    def create(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs (
                    id, user_id,
                    source_type, source_value,
                    status,
                    provider_config_id, provider_name, provider_profile_name,
                    provider_resource_id, provider_status, provider_payload_json,
                    destination_config_id, destination_name, destination_profile_name,
                    output_mode, output_links_json, unrestricted_at,
                    error_message,
                    created_at, updated_at, started_at, completed_at, cancelled_at,
                    send_to_destination, sent_to_destination, sent_to_destination_at,
                    destination_status, destination_message, destination_message_key,
                    destination_message_params, destination_last_attempt, destination_path, destination_progress
                )
                VALUES (
                    %s, %s,
                    %s, %s,
                    %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    job.id,
                    job.user_id,
                    job.source_type,
                    job.source_value,
                    job.status,
                    job.provider_config_id,
                    job.provider_name,
                    job.provider_profile_name,
                    job.provider_resource_id,
                    job.provider_status,
                    job.provider_payload_json,
                    job.destination_config_id,
                    job.destination_name,
                    job.destination_profile_name,
                    job.output_mode,
                    job.output_links_json,
                    job.unrestricted_at,
                    job.error_message,
                    job.created_at,
                    job.updated_at,
                    job.started_at,
                    job.completed_at,
                    job.cancelled_at,
                    job.send_to_destination,
                    job.sent_to_destination,
                    job.sent_to_destination_at,
                    job.destination_status,
                    job.destination_message,
                    job.destination_message_key,
                    job.destination_message_params,
                    job.destination_last_attempt,
                    job.destination_path,
                    job.destination_progress,
                ),
            )

    def get_by_id(self, user_id: str, job_id: str) -> Job | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM jobs
                WHERE id = %s AND user_id = %s
                """,
                (job_id, user_id),
            ).fetchone()

        return self._map_row(row) if row else None

    def list_for_user(self, user_id: str) -> list[Job]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM jobs
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()

        return [self._map_row(row) for row in rows]

    def list_runnable_for_scheduler(self) -> list[Job]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM jobs
                WHERE status IN (
                    'started',
                    'source_added',
                    'downloading',
                    'waiting_files_selection',
                    'downloaded',
                    'ready',
                    'partially_ready'
                )
                AND (
                    destination_status IS NULL
                    OR destination_status NOT IN ('queued', 'sending', 'downloading', 'cancel_requested')
                )
                ORDER BY updated_at ASC
                """
            ).fetchall()

        return [self._map_row(row) for row in rows]

    def get_existing_by_source(
        self,
        user_id: str,
        source_type: str,
        source_value: str,
        provider_config_id: str | None = None,
        provider_name: str | None = None,
    ) -> Job | None:
        if provider_config_id:
            sql = """
                SELECT *
                FROM jobs
                WHERE user_id = %s
                  AND source_type = %s
                  AND source_value = %s
                  AND provider_config_id = %s
                ORDER BY created_at DESC
                LIMIT 1
            """
            params = (user_id, source_type, source_value, provider_config_id)

        elif provider_name:
            # Temporary V2 compatibility fallback.
            sql = """
                SELECT *
                FROM jobs
                WHERE user_id = %s
                  AND source_type = %s
                  AND source_value = %s
                  AND provider_name = %s
                ORDER BY created_at DESC
                LIMIT 1
            """
            params = (user_id, source_type, source_value, provider_name)

        else:
            sql = """
                SELECT *
                FROM jobs
                WHERE user_id = %s
                  AND source_type = %s
                  AND source_value = %s
                  AND provider_config_id IS NULL
                  AND provider_name IS NULL
                ORDER BY created_at DESC
                LIMIT 1
            """
            params = (user_id, source_type, source_value)

        with self.db.connect() as conn:
            row = conn.execute(sql, params).fetchone()

        return self._map_row(row) if row else None

    def _row_get(self, row, key, default=None):
        return row[key] if key in row else default

    def _map_row(self, row) -> Job:
        return Job(
            id=row["id"],
            user_id=row["user_id"],
            source_type=row["source_type"],
            source_value=row["source_value"],
            status=row["status"],
            provider_config_id=self._row_get(row, "provider_config_id"),
            provider_name=row["provider_name"],
            provider_profile_name=self._row_get(row, "provider_profile_name"),
            provider_resource_id=row["provider_resource_id"],
            provider_status=row["provider_status"],
            provider_payload_json=row["provider_payload_json"],
            provider_error_fingerprint=self._row_get(row, "provider_error_fingerprint"),
            destination_config_id=self._row_get(row, "destination_config_id"),
            destination_name=row["destination_name"],
            destination_profile_name=self._row_get(row, "destination_profile_name"),
            output_mode=row["output_mode"],
            output_links_json=row["output_links_json"],
            unrestricted_at=row["unrestricted_at"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            cancelled_at=row["cancelled_at"],
            send_to_destination=bool(row["send_to_destination"]),
            sent_to_destination=bool(row["sent_to_destination"]),
            sent_to_destination_at=row["sent_to_destination_at"],
            destination_status=row["destination_status"],
            destination_message=row["destination_message"],
            destination_message_key=row["destination_message_key"],
            destination_message_params=row["destination_message_params"],
            destination_last_attempt=row["destination_last_attempt"],
            destination_path=row["destination_path"],
            destination_progress=self._row_get(row, "destination_progress", 0),
        )

    def update_provider_state(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = %s,
                    provider_config_id = %s,
                    provider_name = %s,
                    provider_profile_name = %s,
                    provider_resource_id = %s,
                    provider_status = %s,
                    provider_payload_json = %s,
                    provider_error_fingerprint = %s,
                    error_message = %s,
                    updated_at = %s,
                    started_at = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    job.status,
                    job.provider_config_id,
                    job.provider_name,
                    job.provider_profile_name,
                    job.provider_resource_id,
                    job.provider_status,
                    job.provider_payload_json,
                    job.provider_error_fingerprint,
                    job.error_message,
                    job.updated_at,
                    job.started_at,
                    job.id,
                    job.user_id,
                ),
            )

    def record_provider_failure(self, job: Job, fingerprint: str, *, terminal: bool) -> tuple[bool, bool]:
        """Atomically record a provider failure; return (job_exists, first_occurrence)."""
        with self.db.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT provider_error_fingerprint FROM jobs WHERE id = %s AND user_id = %s FOR UPDATE",
                    (job.id, job.user_id),
                )
                row = cur.fetchone()
                if row is None:
                    return False, False
                first = row["provider_error_fingerprint"] != fingerprint
                if terminal:
                    cur.execute(
                        """UPDATE jobs SET status = 'failed', provider_status = 'failed',
                           error_message = %s, provider_error_fingerprint = %s, updated_at = %s, completed_at = %s
                           WHERE id = %s AND user_id = %s""",
                        (job.error_message, fingerprint, job.updated_at, job.completed_at, job.id, job.user_id),
                    )
                elif first:
                    cur.execute(
                        "UPDATE jobs SET provider_error_fingerprint = %s, error_message = %s, updated_at = %s WHERE id = %s AND user_id = %s",
                        (fingerprint, job.error_message, job.updated_at, job.id, job.user_id),
                    )
            conn.commit()
            return True, first

    def update_refresh_state(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = %s,
                    provider_status = %s,
                    provider_payload_json = %s,
                    provider_error_fingerprint = %s,
                    error_message = %s,
                    updated_at = %s,
                    completed_at = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    job.status,
                    job.provider_status,
                    job.provider_payload_json,
                    job.provider_error_fingerprint,
                    job.error_message,
                    job.updated_at,
                    job.completed_at,
                    job.id,
                    job.user_id,
                ),
            )

    def update_after_select_files(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = %s,
                    provider_status = %s,
                    provider_payload_json = %s,
                    provider_error_fingerprint = %s,
                    error_message = %s,
                    updated_at = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    job.status,
                    job.provider_status,
                    job.provider_payload_json,
                    job.provider_error_fingerprint,
                    job.error_message,
                    job.updated_at,
                    job.id,
                    job.user_id,
                ),
            )

    def update_unrestrict_state(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = %s,
                    output_mode = %s,
                    output_links_json = %s,
                    unrestricted_at = %s,
                    provider_error_fingerprint = %s,
                    error_message = %s,
                    updated_at = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    job.status,
                    job.output_mode,
                    job.output_links_json,
                    job.unrestricted_at,
                    job.provider_error_fingerprint,
                    job.error_message,
                    job.updated_at,
                    job.id,
                    job.user_id,
                ),
            )

    def update_destination_state(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = %s,
                    destination_config_id = %s,
                    destination_name = %s,
                    destination_profile_name = %s,
                    send_to_destination = %s,
                    sent_to_destination = %s,
                    sent_to_destination_at = %s,
                    destination_status = %s,
                    destination_message = %s,
                    destination_message_key = %s,
                    destination_message_params = %s,
                    destination_last_attempt = %s,
                    destination_path = %s,
                    destination_progress = %s,
                    error_message = %s,
                    updated_at = %s,
                    completed_at = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    job.status,
                    job.destination_config_id,
                    job.destination_name,
                    job.destination_profile_name,
                    job.send_to_destination,
                    job.sent_to_destination,
                    job.sent_to_destination_at,
                    job.destination_status,
                    job.destination_message,
                    job.destination_message_key,
                    job.destination_message_params,
                    job.destination_last_attempt,
                    job.destination_path,
                    job.destination_progress,
                    job.error_message,
                    job.updated_at,
                    job.completed_at,
                    job.id,
                    job.user_id,
                ),
            )

    def update_full_reset(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = %s,
                    provider_resource_id = %s,
                    provider_status = %s,
                    provider_payload_json = %s,
                    provider_error_fingerprint = %s,
                    output_mode = %s,
                    output_links_json = %s,
                    unrestricted_at = %s,
                    error_message = %s,
                    started_at = %s,
                    completed_at = %s,
                    cancelled_at = %s,
                    sent_to_destination = %s,
                    sent_to_destination_at = %s,
                    destination_status = %s,
                    destination_message = %s,
                    destination_message_key = %s,
                    destination_message_params = %s,
                    destination_last_attempt = %s,
                    destination_path = %s,
                    destination_progress = %s,
                    updated_at = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    job.status,
                    job.provider_resource_id,
                    job.provider_status,
                    job.provider_payload_json,
                    job.provider_error_fingerprint,
                    job.output_mode,
                    job.output_links_json,
                    job.unrestricted_at,
                    job.error_message,
                    job.started_at,
                    job.completed_at,
                    job.cancelled_at,
                    job.sent_to_destination,
                    job.sent_to_destination_at,
                    job.destination_status,
                    job.destination_message,
                    job.destination_message_key,
                    job.destination_message_params,
                    job.destination_last_attempt,
                    job.destination_path,
                    job.destination_progress,
                    job.updated_at,
                    job.id,
                    job.user_id,
                ),
            )

    def update_status_state(self, job: Job) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = %s,
                    error_message = %s,
                    updated_at = %s,
                    completed_at = %s,
                    cancelled_at = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    job.status,
                    job.error_message,
                    job.updated_at,
                    job.completed_at,
                    job.cancelled_at,
                    job.id,
                    job.user_id,
                ),
            )

    def delete(self, user_id: str, job_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                DELETE FROM jobs
                WHERE id = %s AND user_id = %s
                """,
                (job_id, user_id),
            )

    def cleanup_by_status_before(self, status: str, cutoff_iso: str) -> int:
        with self.db.connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM jobs
                WHERE status = %s
                  AND COALESCE(completed_at, cancelled_at, updated_at, created_at) <= %s
                """,
                (status, cutoff_iso),
            )

            return int(cursor.rowcount or 0)
