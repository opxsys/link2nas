APP_PUBLIC_BASE_URL_KEY = "app.public_base_url"
APP_NAME_KEY = "app.name"
APP_TAGLINE_KEY = "app.tagline"

ANNOUNCEMENTS_ENABLED_KEY = "announcements.enabled"
DEFAULT_ANNOUNCEMENTS_SETTINGS = {"enabled": True}

SECURITY_TOKEN_TTL_KEY = "security.token_ttl"
SECURITY_PASSWORD_POLICY_KEY = "security.password_policy"
CLEANUP_RETENTION_KEY = "cleanup.retention"
RESTART_COOLDOWN_KEY = "jobs.restart_cooldown"
NOTIFICATION_DISPATCHER_KEY = "notifications.dispatcher"
NOTIFICATION_EVENT_POLICY_KEY = "notifications.event_policy"
JOBS_ORCHESTRATOR_KEY = "jobs.orchestrator"
LOCAL_DOWNLOAD_WORKER_KEY = "downloads.local_worker"
NOTIFICATION_DISPATCHER_RUNTIME_KEY = "notifications.dispatcher.runtime"
SYSTEM_EVENTS_DEDUP_KEY = "system_events.dedup"

DEFAULT_APP_NAME = "Link2NAS"
DEFAULT_APP_TAGLINE = "Job management + debrid provider"

DEFAULT_SYSTEM_EVENTS_DEDUP = {
    "enabled": True,
    "dedup_minutes": 60,
}

DEFAULT_NOTIFICATION_DISPATCHER_RUNTIME = {
    "last_run_at": None,
    "last_error": None,
    "last_result": None,
}

DEFAULT_NOTIFICATION_DISPATCHER = {
    "enabled": True,
    "interval_seconds": 60,
    "limit": 25,
}

DEFAULT_NOTIFICATION_EVENT_POLICY = {
    "max_age_hours": 24,
}

DEFAULT_JOBS_ORCHESTRATOR = {
    "enabled": True,
    "interval_seconds": 5,
    "max_jobs_per_run": 25,
    "auto_refresh_enabled": True,
    "auto_unrestrict_enabled": True,
    "auto_send_destination_enabled": True,
}

DEFAULT_LOCAL_DOWNLOAD_WORKER = {
    "enabled": True,
    "poll_interval_seconds": 5,
    "max_concurrent_downloads": 1,
}

DEFAULT_SECURITY_TOKEN_TTL = {
    "invitation_ttl_hours": 48,
    "password_reset_ttl_hours": 2,
    "magic_login_ttl_minutes": 15,
    "email_verification_ttl_hours": 24,
    "session_inactivity_minutes": 30,
}

DEFAULT_SECURITY_PASSWORD_POLICY = {
    "min_length": 10,
    "require_uppercase": False,
    "require_lowercase": False,
    "require_number": False,
    "require_special": False,
}

DEFAULT_CLEANUP_RETENTION = {
    "torrent_tmp_days": 7,
    "completed_jobs_days": 30,
    "failed_jobs_days": 30,
    "cancelled_jobs_days": 15,
    "expired_tokens_days": 7,
}

DEFAULT_RESTART_COOLDOWNS = {
    "default_seconds": 10,
    "realdebrid_seconds": 60,
    "alldebrid_seconds": 8,
}
