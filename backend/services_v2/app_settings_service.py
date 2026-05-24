from datetime import UTC, datetime

from backend.services_v2.app_settings_support.defaults import (
    APP_NAME_KEY,
    APP_PUBLIC_BASE_URL_KEY,
    APP_TAGLINE_KEY,
    CLEANUP_RETENTION_KEY,
    DEFAULT_APP_NAME,
    DEFAULT_APP_TAGLINE,
    DEFAULT_CLEANUP_RETENTION,
    DEFAULT_JOBS_ORCHESTRATOR,
    DEFAULT_LOCAL_DOWNLOAD_WORKER,
    DEFAULT_NOTIFICATION_DISPATCHER,
    DEFAULT_NOTIFICATION_DISPATCHER_RUNTIME,
    DEFAULT_RESTART_COOLDOWNS,
    DEFAULT_SECURITY_PASSWORD_POLICY,
    DEFAULT_SECURITY_TOKEN_TTL,
    DEFAULT_SYSTEM_EVENTS_DEDUP,
    JOBS_ORCHESTRATOR_KEY,
    LOCAL_DOWNLOAD_WORKER_KEY,
    NOTIFICATION_DISPATCHER_KEY,
    NOTIFICATION_DISPATCHER_RUNTIME_KEY,
    RESTART_COOLDOWN_KEY,
    SECURITY_PASSWORD_POLICY_KEY,
    SECURITY_TOKEN_TTL_KEY,
    SYSTEM_EVENTS_DEDUP_KEY,
)
from backend.services_v2.app_settings_support.validation import (
    AppSettingsValidationError,
    validate_int,
)
from backend.services_v2.app_settings_support.storage import (
    get_json_setting,
    get_string_setting,
    merge_with_default,
    save_json_setting,
    save_string_setting,
)


class AppSettingsService:
    def __init__(self, repository):
        self.repository = repository

    def now(self) -> str:
        return datetime.now(UTC).isoformat()

    def get_security_settings(self) -> dict:
        return {
            "token_ttl": self.get_security_token_ttl(),
            "password_policy": self.get_password_policy(),
        }

    def save_security_settings(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise AppSettingsValidationError("payload must be an object")

        token_ttl = payload.get("token_ttl") or {}
        password_policy = payload.get("password_policy") or {}

        if not isinstance(token_ttl, dict):
            raise AppSettingsValidationError("token_ttl must be an object")

        if not isinstance(password_policy, dict):
            raise AppSettingsValidationError("password_policy must be an object")

        saved_token_ttl = self.save_security_token_ttl(token_ttl)
        saved_password_policy = self.save_password_policy(password_policy)

        return {
            "token_ttl": saved_token_ttl,
            "password_policy": saved_password_policy,
        }

    def get_cleanup_settings(self) -> dict:
        return {
            "retention": self.get_cleanup_retention(),
        }

    def save_cleanup_settings(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise AppSettingsValidationError("payload must be an object")

        retention = payload.get("retention") or {}

        if not isinstance(retention, dict):
            raise AppSettingsValidationError("retention must be an object")

        saved_retention = self.save_cleanup_retention(retention)

        return {
            "retention": saved_retention,
        }

    def get_system_events_settings(self) -> dict:
        return {
            "dedup": self.get_system_events_dedup(),
        }

    def save_system_events_settings(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise AppSettingsValidationError("payload must be an object")

        dedup = payload.get("dedup") or {}

        if not isinstance(dedup, dict):
            raise AppSettingsValidationError("dedup must be an object")

        saved_dedup = self.save_system_events_dedup(dedup)

        return {
            "dedup": saved_dedup,
        }

    def get_security_token_ttl(self) -> dict:
        return self._get_json_setting(
            SECURITY_TOKEN_TTL_KEY,
            DEFAULT_SECURITY_TOKEN_TTL,
        )

    def save_security_token_ttl(self, value: dict) -> dict:
        merged = merge_with_default(DEFAULT_SECURITY_TOKEN_TTL, value)

        constraints = {
            "invitation_ttl_hours": (1, 24 * 14),
            "password_reset_ttl_hours": (1, 24),
            "magic_login_ttl_minutes": (5, 120),
            "email_verification_ttl_hours": (1, 24 * 7),
            "session_inactivity_minutes": (5, 24 * 60),
        }

        for key, (min_value, max_value) in constraints.items():
            merged[key] = validate_int(
                merged.get(key),
                key,
                min_value=min_value,
                max_value=max_value,
            )

        self._save_json_setting(SECURITY_TOKEN_TTL_KEY, merged)
        return merged

    def get_password_policy(self) -> dict:
        return self._get_json_setting(
            SECURITY_PASSWORD_POLICY_KEY,
            DEFAULT_SECURITY_PASSWORD_POLICY,
        )

    def save_password_policy(self, value: dict) -> dict:
        merged = merge_with_default(DEFAULT_SECURITY_PASSWORD_POLICY, value)

        merged["min_length"] = validate_int(
            merged.get("min_length"),
            "min_length",
            min_value=8,
            max_value=128,
        )

        for key in (
            "require_uppercase",
            "require_lowercase",
            "require_number",
            "require_special",
        ):
            merged[key] = bool(merged.get(key))

        self._save_json_setting(SECURITY_PASSWORD_POLICY_KEY, merged)
        return merged

    def get_cleanup_retention(self) -> dict:
        return self._get_json_setting(
            CLEANUP_RETENTION_KEY,
            DEFAULT_CLEANUP_RETENTION,
        )

    def save_cleanup_retention(self, value: dict) -> dict:
        merged = merge_with_default(DEFAULT_CLEANUP_RETENTION, value)

        constraints = {
            "torrent_tmp_days": (1, 365),
            "completed_jobs_days": (1, 3650),
            "failed_jobs_days": (1, 3650),
            "cancelled_jobs_days": (1, 3650),
            "expired_tokens_days": (1, 365),
        }

        for key, (min_value, max_value) in constraints.items():
            merged[key] = validate_int(
                merged.get(key),
                key,
                min_value=min_value,
                max_value=max_value,
            )

        self._save_json_setting(CLEANUP_RETENTION_KEY, merged)
        return merged

    def get_system_events_dedup(self) -> dict:
        return self._get_json_setting(
            SYSTEM_EVENTS_DEDUP_KEY,
            DEFAULT_SYSTEM_EVENTS_DEDUP,
        )

    def save_system_events_dedup(self, value: dict) -> dict:
        merged = merge_with_default(DEFAULT_SYSTEM_EVENTS_DEDUP, value)

        merged["enabled"] = bool(merged.get("enabled", True))
        merged["dedup_minutes"] = validate_int(
            merged.get("dedup_minutes"),
            "dedup_minutes",
            min_value=1,
            max_value=1440,
        )

        self._save_json_setting(SYSTEM_EVENTS_DEDUP_KEY, merged)
        return merged

    def get_invitation_ttl_hours(self) -> int:
        return int(self.get_security_token_ttl()["invitation_ttl_hours"])

    def get_password_reset_ttl_hours(self) -> int:
        return int(self.get_security_token_ttl()["password_reset_ttl_hours"])

    def get_magic_login_ttl_minutes(self) -> int:
        return int(self.get_security_token_ttl()["magic_login_ttl_minutes"])

    def get_email_verification_ttl_hours(self) -> int:
        return int(self.get_security_token_ttl()["email_verification_ttl_hours"])

    def get_session_inactivity_minutes(self) -> int:
        return int(self.get_security_token_ttl()["session_inactivity_minutes"])

    def get_restart_cooldowns(self) -> dict:
        return self._get_json_setting(
            RESTART_COOLDOWN_KEY,
            DEFAULT_RESTART_COOLDOWNS,
        )

    def save_restart_cooldowns(self, value: dict) -> dict:
        if not isinstance(value, dict):
            raise AppSettingsValidationError("restart_cooldowns must be an object")

        merged = merge_with_default(DEFAULT_RESTART_COOLDOWNS, value)

        constraints = {
            "default_seconds": (0, 3600),
            "realdebrid_seconds": (0, 3600),
            "alldebrid_seconds": (0, 3600),
        }

        for key, (min_value, max_value) in constraints.items():
            merged[key] = validate_int(
                merged.get(key),
                key,
                min_value=min_value,
                max_value=max_value,
            )

        self._save_json_setting(RESTART_COOLDOWN_KEY, merged)
        return merged

    def get_notification_dispatcher_settings(self) -> dict:
        return self._get_json_setting(
            NOTIFICATION_DISPATCHER_KEY,
            DEFAULT_NOTIFICATION_DISPATCHER,
        )

    def save_notification_dispatcher_settings(self, value: dict) -> dict:
        if not isinstance(value, dict):
            raise AppSettingsValidationError("notifications.dispatcher must be an object")

        merged = merge_with_default(DEFAULT_NOTIFICATION_DISPATCHER, value)

        merged["enabled"] = bool(merged.get("enabled"))
        merged["interval_seconds"] = validate_int(
            merged.get("interval_seconds"),
            "interval_seconds",
            min_value=5,
            max_value=86400,
        )
        merged["limit"] = validate_int(
            merged.get("limit"),
            "limit",
            min_value=1,
            max_value=200,
        )

        self._save_json_setting(NOTIFICATION_DISPATCHER_KEY, merged)
        return merged

    def get_jobs_orchestrator_settings(self) -> dict:
        return self._get_json_setting(
            JOBS_ORCHESTRATOR_KEY,
            DEFAULT_JOBS_ORCHESTRATOR,
        )

    def save_jobs_orchestrator_settings(self, value: dict) -> dict:
        if not isinstance(value, dict):
            raise AppSettingsValidationError("jobs.orchestrator must be an object")

        merged = merge_with_default(DEFAULT_JOBS_ORCHESTRATOR, value)

        merged["enabled"] = bool(merged.get("enabled"))
        merged["interval_seconds"] = validate_int(
            merged.get("interval_seconds"),
            "interval_seconds",
            min_value=1,
            max_value=3600,
        )
        merged["max_jobs_per_run"] = validate_int(
            merged.get("max_jobs_per_run"),
            "max_jobs_per_run",
            min_value=1,
            max_value=500,
        )
        merged["auto_refresh_enabled"] = bool(merged.get("auto_refresh_enabled"))
        merged["auto_unrestrict_enabled"] = bool(merged.get("auto_unrestrict_enabled"))
        merged["auto_send_destination_enabled"] = bool(merged.get("auto_send_destination_enabled"))

        self._save_json_setting(JOBS_ORCHESTRATOR_KEY, merged)
        return merged

    def get_local_download_worker_settings(self) -> dict:
        return self._get_json_setting(
            LOCAL_DOWNLOAD_WORKER_KEY,
            DEFAULT_LOCAL_DOWNLOAD_WORKER,
        )

    def save_local_download_worker_settings(self, value: dict) -> dict:
        if not isinstance(value, dict):
            raise AppSettingsValidationError("downloads.local_worker must be an object")

        merged = merge_with_default(DEFAULT_LOCAL_DOWNLOAD_WORKER, value)

        merged["enabled"] = bool(merged.get("enabled"))
        merged["poll_interval_seconds"] = validate_int(
            merged.get("poll_interval_seconds"),
            "poll_interval_seconds",
            min_value=1,
            max_value=3600,
        )
        merged["max_concurrent_downloads"] = validate_int(
            merged.get("max_concurrent_downloads"),
            "max_concurrent_downloads",
            min_value=1,
            max_value=20,
        )

        self._save_json_setting(LOCAL_DOWNLOAD_WORKER_KEY, merged)
        return merged

    def get_runtime_settings(self) -> dict:
        return {
            "notifications": {
                "dispatcher": {
                    **self.get_notification_dispatcher_settings(),
                    **self.get_notification_dispatcher_runtime(),
                },
            },
            "jobs": {
                "orchestrator": self.get_jobs_orchestrator_settings(),
            },
            "downloads": {
                "local_worker": self.get_local_download_worker_settings(),
            },
        }

    def save_runtime_settings(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise AppSettingsValidationError("payload must be an object")

        notifications = payload.get("notifications") or {}
        jobs = payload.get("jobs") or {}
        downloads = payload.get("downloads") or {}

        if not isinstance(notifications, dict):
            raise AppSettingsValidationError("notifications must be an object")

        if not isinstance(jobs, dict):
            raise AppSettingsValidationError("jobs must be an object")

        if not isinstance(downloads, dict):
            raise AppSettingsValidationError("downloads must be an object")

        dispatcher = notifications.get("dispatcher") or {}
        orchestrator = jobs.get("orchestrator") or {}
        local_worker = downloads.get("local_worker") or {}

        return {
            "notifications": {
                "dispatcher": self.save_notification_dispatcher_settings(dispatcher),
            },
            "jobs": {
                "orchestrator": self.save_jobs_orchestrator_settings(orchestrator),
            },
            "downloads": {
                "local_worker": self.save_local_download_worker_settings(local_worker),
            },
        }

    def get_notification_dispatcher_runtime(self) -> dict:
        return self._get_json_setting(
            NOTIFICATION_DISPATCHER_RUNTIME_KEY,
            DEFAULT_NOTIFICATION_DISPATCHER_RUNTIME,
        )

    def save_notification_dispatcher_runtime(self, result: dict | None, last_error: str | None = None) -> dict:
        if result is None:
            result = {}

        if not isinstance(result, dict):
            raise AppSettingsValidationError("dispatcher runtime result must be an object")

        finished_at = result.get("finished_at") or result.get("last_run_at") or None

        runtime = {
            "last_run_at": finished_at,
            "last_error": last_error,
            "last_result": result,
        }

        self._save_json_setting(NOTIFICATION_DISPATCHER_RUNTIME_KEY, runtime)
        return runtime

    def get_public_base_url_override(self) -> str:
        stored = self._get_string_setting(APP_PUBLIC_BASE_URL_KEY)
        return stored or ""

    def get_effective_public_base_url(self, env_fallback: str = "") -> str:
        stored = self._get_string_setting(APP_PUBLIC_BASE_URL_KEY)
        return stored if stored else (env_fallback or "")

    def save_public_base_url(self, url: str) -> str:
        url = str(url or "").strip().rstrip("/")
        if url:
            if not (url.startswith("http://") or url.startswith("https://")):
                raise AppSettingsValidationError(
                    "PUBLIC_BASE_URL must start with http:// or https://"
                )
        self._save_string_setting(APP_PUBLIC_BASE_URL_KEY, url)
        return url

    def get_general_settings(self, env_name: str = "", env_tagline: str = "", env_url: str = "") -> dict:
        return {
            "app_name": self.get_effective_app_name(env_name),
            "app_tagline": self.get_effective_app_tagline(env_tagline),
            "public_base_url": self.get_public_base_url_override(),
            "effective_public_base_url": self.get_effective_public_base_url(env_url),
        }

    def save_general_settings(self, data: dict, env_name: str = "", env_tagline: str = "", env_url: str = "") -> dict:
        if not isinstance(data, dict):
            raise AppSettingsValidationError("payload must be an object")
        if "app_name" in data:
            self.save_app_name(data["app_name"])
        if "app_tagline" in data:
            self.save_app_tagline(data["app_tagline"])
        if "public_base_url" in data:
            self.save_public_base_url(data["public_base_url"])
        return self.get_general_settings(env_name, env_tagline, env_url)

    def get_effective_app_name(self, env_fallback: str = "") -> str:
        stored = self._get_string_setting(APP_NAME_KEY)
        return stored if stored else (env_fallback or DEFAULT_APP_NAME)

    def get_effective_app_tagline(self, env_fallback: str = "") -> str:
        stored = self._get_string_setting(APP_TAGLINE_KEY)
        return stored if stored else (env_fallback or DEFAULT_APP_TAGLINE)

    def save_app_name(self, value: str) -> str:
        name = str(value or "").strip()
        if not name:
            raise AppSettingsValidationError("App name cannot be empty")
        if len(name) > 100:
            raise AppSettingsValidationError("App name must be 100 characters or fewer")
        self._save_string_setting(APP_NAME_KEY, name)
        return name

    def save_app_tagline(self, value: str) -> str:
        tagline = str(value or "").strip()
        if len(tagline) > 200:
            raise AppSettingsValidationError("Tagline must be 200 characters or fewer")
        self._save_string_setting(APP_TAGLINE_KEY, tagline)
        return tagline


    # -------------------------------------------------------------------------
    # Storage helpers
    # -------------------------------------------------------------------------

    def _get_json_setting(self, key: str, default: dict) -> dict:
        return get_json_setting(self.repository, key, default)

    def _save_json_setting(self, key: str, value: dict) -> None:
        save_json_setting(self.repository, key, value, self.now)

    def _get_string_setting(self, key: str) -> str | None:
        return get_string_setting(self.repository, key)

    def _save_string_setting(self, key: str, value: str) -> None:
        save_string_setting(self.repository, key, value, self.now)

