from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass
class CleanupResult:
    enabled: bool
    started_at: str
    finished_at: str | None
    tokens_deleted: int = 0
    completed_jobs_deleted: int = 0
    failed_jobs_deleted: int = 0
    cancelled_jobs_deleted: int = 0
    temp_files_deleted: int = 0
    temp_files_errors: list[str] | None = None

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "tokens_deleted": self.tokens_deleted,
            "completed_jobs_deleted": self.completed_jobs_deleted,
            "failed_jobs_deleted": self.failed_jobs_deleted,
            "cancelled_jobs_deleted": self.cancelled_jobs_deleted,
            "temp_files_deleted": self.temp_files_deleted,
            "temp_files_errors": self.temp_files_errors or [],
        }


class CleanupService:
    def __init__(
        self,
        *,
        settings,
        app_settings_service,
        job_repository,
        account_token_repository,
    ):
        self.settings = settings
        self.app_settings_service = app_settings_service
        self.job_repository = job_repository
        self.account_token_repository = account_token_repository

    def now(self) -> datetime:
        return datetime.now(UTC)

    def now_iso(self) -> str:
        return self.now().isoformat()

    def run(self) -> CleanupResult:
        started_at = self.now_iso()

        result = CleanupResult(
            enabled=bool(getattr(self.settings, "CLEANUP_ENABLED", True)),
            started_at=started_at,
            finished_at=None,
            temp_files_errors=[],
        )

        if not result.enabled:
            result.finished_at = self.now_iso()
            return result

        retention = self.app_settings_service.get_cleanup_retention()

        result.tokens_deleted = self.cleanup_tokens(
            days=int(retention["expired_tokens_days"])
        )

        result.completed_jobs_deleted = self.cleanup_jobs(
            status="completed",
            days=int(retention["completed_jobs_days"]),
        )

        result.failed_jobs_deleted = self.cleanup_jobs(
            status="failed",
            days=int(retention["failed_jobs_days"]),
        )

        result.cancelled_jobs_deleted = self.cleanup_jobs(
            status="cancelled",
            days=int(retention["cancelled_jobs_days"]),
        )

        temp_deleted, temp_errors = self.cleanup_temp_files(
            days=int(retention["torrent_tmp_days"])
        )

        result.temp_files_deleted = temp_deleted
        result.temp_files_errors = temp_errors
        result.finished_at = self.now_iso()

        return result

    def cutoff_iso(self, days: int) -> str:
        return (self.now() - timedelta(days=int(days))).isoformat()

    def cleanup_tokens(self, *, days: int) -> int:
        return self.account_token_repository.cleanup_old_tokens(
            self.cutoff_iso(days)
        )

    def cleanup_jobs(self, *, status: str, days: int) -> int:
        return self.job_repository.cleanup_by_status_before(
            status,
            self.cutoff_iso(days),
        )

    def cleanup_temp_files(self, *, days: int) -> tuple[int, list[str]]:
        directories = [
            Path(getattr(self.settings, "TEMP_DIR", "./tmp")).resolve(),
            Path(getattr(self.settings, "TORRENT_DIR", "./data/torrents")).resolve(),
        ]

        cutoff = self.now() - timedelta(days=int(days))

        deleted = 0
        errors: list[str] = []

        allowed_suffixes = {".torrent", ".tmp", ".part"}

        for directory in directories:
            if not directory.exists():
                continue

            if not directory.is_dir():
                errors.append(f"{directory} is not a directory")
                continue

            for path in directory.rglob("*"):
                try:
                    if not path.is_file():
                        continue

                    if path.suffix.lower() not in allowed_suffixes:
                        continue

                    modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)

                    if modified_at > cutoff:
                        continue

                    path.unlink()
                    deleted += 1
                except Exception as exc:
                    errors.append(f"{path}: {exc}")

        return deleted, errors
