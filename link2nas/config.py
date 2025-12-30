from __future__ import annotations

import os
from dataclasses import dataclass


# =========================
# helpers env
# =========================
def env(name: str, default: str | None = None) -> str:
    """
    Read env var.
    - If default is None: variable is required (raises)
    - Else: returns default when missing/empty
    """
    v = os.getenv(name)
    if v is None or str(v).strip() == "":
        if default is None:
            raise RuntimeError(f"Missing required env var: {name}")
        return default
    return v


def env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    v = str(os.getenv(name, "")).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def env_set(name: str, default: set[str]) -> set[str]:
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return default
    return {p.strip() for p in raw.split(",") if p.strip()}


def has_synology_config(synology_url: str, synology_user: str, synology_password: str) -> bool:
    return bool(str(synology_url or "").strip() and str(synology_user or "").strip() and str(synology_password or "").strip())


def normalize_csv(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw == "*":
        return "*"
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return ",".join(parts)


# =========================
# SAFE module-level defaults (no required env here)
# =========================
DEFAULT_APP_VERSION = os.getenv("APP_VERSION", "dev")
DEFAULT_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper().strip() or "INFO"
DEFAULT_CORS_ORIGINS = normalize_csv(os.getenv("CORS_ORIGINS", ""))

DEFAULT_NOISY_PATHS = env_set("NOISY_PATHS", {"/api/pending_torrents", "/api/completed_torrents"})

DEFAULT_ADMIN_ENABLED = env_bool("ADMIN_ENABLED", True)
DEFAULT_ADMIN_UI_ENABLED = env_bool("ADMIN_UI_ENABLED", True)
DEFAULT_ADMIN_USER = os.getenv("ADMIN_USER", "admin")
DEFAULT_ADMIN_REALM = os.getenv("ADMIN_REALM", "Admin")

DEFAULT_REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
DEFAULT_REDIS_PORT = env_int("REDIS_PORT", 6379)
DEFAULT_REDIS_DB = env_int("REDIS_DB", 0)

DEFAULT_DSM_LOGIN_TIMEOUT = env_int("DSM_LOGIN_TIMEOUT", 10)
DEFAULT_DSM_TASK_TIMEOUT = env_int("DSM_TASK_TIMEOUT", 30)
DEFAULT_DSM_LOGOUT_TIMEOUT = env_int("DSM_LOGOUT_TIMEOUT", 5)

DEFAULT_STATUS_ROUTE_ENABLED = env_bool("STATUS_ROUTE_ENABLED", True)
DEFAULT_STATUS_HTTP_TIMEOUT = env_int("STATUS_HTTP_TIMEOUT", 6)
DEFAULT_STATUS_DSM_TIMEOUT = env_int("STATUS_DSM_TIMEOUT", 6)
DEFAULT_PREMIUM_GREEN_DAYS = env_int("PREMIUM_GREEN_DAYS", 14)
DEFAULT_PREMIUM_YELLOW_DAYS = env_int("PREMIUM_YELLOW_DAYS", 7)

DEFAULT_SCHEDULER_ENABLED = env_bool("SCHEDULER_ENABLED", False)
DEFAULT_SCHEDULER_INTERVAL_SECONDS = env_int("SCHEDULER_INTERVAL_SECONDS", 10)
DEFAULT_SCHEDULER_MAX_INSTANCES = env_int("SCHEDULER_MAX_INSTANCES", 1)
DEFAULT_SCHEDULER_COALESCE = env_bool("SCHEDULER_COALESCE", True)
DEFAULT_SCHEDULER_MISFIRE_GRACE_SECONDS = env_int("SCHEDULER_MISFIRE_GRACE_SECONDS", 30)
DEFAULT_MAX_UNLOCK_PER_RUN = env_int("MAX_UNLOCK_PER_RUN", 30)


# =========================
# Settings object used by webapp/create_app
# =========================
@dataclass(frozen=True, slots=True)
class Settings:
    # App
    app_version: str
    flask_secret_key: str

    # CORS / Logging
    cors_origins: str
    log_level: str
    noisy_paths: set[str]

    # Admin auth / UI
    admin_enabled: bool
    admin_ui_enabled: bool
    admin_user: str
    admin_pass: str
    admin_realm: str

    # AllDebrid
    alldebrid_base_url: str
    alldebrid_apikey: str
    alldebrid_timeout: int
    ad_ping_path: str
    ad_endpoints: dict[str, str]

    # Redis
    redis_host: str
    redis_port: int
    redis_db: int

    # Synology / NAS
    synology_url: str
    synology_user: str
    synology_password: str
    dsm_login_timeout: int
    dsm_task_timeout: int
    dsm_logout_timeout: int
    nas_enabled: bool

    # Status page
    status_route_enabled: bool
    status_http_timeout: int
    status_dsm_timeout: int
    premium_green_days: int
    premium_yellow_days: int

    # Scheduler
    scheduler_enabled: bool
    scheduler_interval_seconds: int
    scheduler_max_instances: int
    scheduler_coalesce: bool
    scheduler_misfire_grace_seconds: int
    max_unlock_per_run: int

    def __repr__(self) -> str:
        # IMPORTANT: never print secrets (apikey/password/secret/sid/etc)
        return (
            "Settings("
            f"app_version={self.app_version!r}, "
            f"log_level={self.log_level!r}, "
            f"cors_origins={self.cors_origins!r}, "
            f"noisy_paths={sorted(self.noisy_paths)!r}, "
            f"admin_enabled={self.admin_enabled}, "
            f"admin_ui_enabled={self.admin_ui_enabled}, "
            f"admin_user={self.admin_user!r}, "
            f"admin_realm={self.admin_realm!r}, "
            f"redis={self.redis_host}:{self.redis_port}/{self.redis_db}, "
            f"alldebrid_base_url={self.alldebrid_base_url!r}, "
            f"alldebrid_timeout={self.alldebrid_timeout}, "
            f"nas_enabled={self.nas_enabled}, "
            f"status_route_enabled={self.status_route_enabled}, "
            f"scheduler_enabled={self.scheduler_enabled}, "
            f"max_unlock_per_run={self.max_unlock_per_run}"
            ")"
        )

    @classmethod
    def from_env(cls) -> "Settings":
        # App (required)
        app_version = os.getenv("APP_VERSION", DEFAULT_APP_VERSION)
        flask_secret_key = env("FLASK_SECRET_KEY")

        log_level = os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper().strip() or "INFO"
        cors_origins = normalize_csv(os.getenv("CORS_ORIGINS", DEFAULT_CORS_ORIGINS))
        noisy_paths = env_set("NOISY_PATHS", DEFAULT_NOISY_PATHS)

        # Admin
        admin_enabled = env_bool("ADMIN_ENABLED", DEFAULT_ADMIN_ENABLED)
        admin_ui_enabled = env_bool("ADMIN_UI_ENABLED", DEFAULT_ADMIN_UI_ENABLED)
        admin_user = os.getenv("ADMIN_USER", DEFAULT_ADMIN_USER)
        admin_pass = os.getenv("ADMIN_PASS", "")
        admin_realm = os.getenv("ADMIN_REALM", DEFAULT_ADMIN_REALM)

        if admin_enabled and not str(admin_pass).strip():
            raise RuntimeError("ADMIN_ENABLED=1 but ADMIN_PASS is empty")

        # Redis
        redis_host = os.getenv("REDIS_HOST", DEFAULT_REDIS_HOST)
        redis_port = env_int("REDIS_PORT", DEFAULT_REDIS_PORT)
        redis_db = env_int("REDIS_DB", DEFAULT_REDIS_DB)

        # AllDebrid (ALL REQUIRED)
        alldebrid_apikey = env("ALLDEBRID_APIKEY")
        alldebrid_base_url = env("ALLDEBRID_BASE_URL")
        ad_endpoints = {
            "user": env("ALLDEBRID_API_USER"),
            "magnet_upload": env("ALLDEBRID_API_MAGNET_UPLOAD"),
            "magnet_status": env("ALLDEBRID_API_MAGNET_STATUS"),
            "magnet_files": env("ALLDEBRID_API_MAGNET_FILES"),
            "magnet_delete": env("ALLDEBRID_API_MAGNET_DELETE"),
            "link_unlock": env("ALLDEBRID_API_LINK_UNLOCK"),
        }
        alldebrid_timeout = env_int("ALLDEBRID_TIMEOUT", 60)
        ad_ping_path = env("ALLDEBRID_API_PING", "/v4/ping")

        # Synology / NAS (optional)
        synology_url = str(os.getenv("SYNOLOGY_URL", "")).strip().rstrip("/")
        synology_user = str(os.getenv("SYNOLOGY_USER", "")).strip()
        synology_password = str(os.getenv("SYNOLOGY_PASSWORD", "")).strip()

        dsm_login_timeout = env_int("DSM_LOGIN_TIMEOUT", DEFAULT_DSM_LOGIN_TIMEOUT)
        dsm_task_timeout = env_int("DSM_TASK_TIMEOUT", DEFAULT_DSM_TASK_TIMEOUT)
        dsm_logout_timeout = env_int("DSM_LOGOUT_TIMEOUT", DEFAULT_DSM_LOGOUT_TIMEOUT)

        nas_flag = env_bool("NAS_ENABLED", True)
        nas_enabled = nas_flag and has_synology_config(synology_url, synology_user, synology_password)

        # Status page
        status_route_enabled = env_bool("STATUS_ROUTE_ENABLED", DEFAULT_STATUS_ROUTE_ENABLED)
        status_http_timeout = env_int("STATUS_HTTP_TIMEOUT", DEFAULT_STATUS_HTTP_TIMEOUT)
        status_dsm_timeout = env_int("STATUS_DSM_TIMEOUT", DEFAULT_STATUS_DSM_TIMEOUT)
        premium_green_days = env_int("PREMIUM_GREEN_DAYS", DEFAULT_PREMIUM_GREEN_DAYS)
        premium_yellow_days = env_int("PREMIUM_YELLOW_DAYS", DEFAULT_PREMIUM_YELLOW_DAYS)

        # Scheduler
        scheduler_enabled = env_bool("SCHEDULER_ENABLED", DEFAULT_SCHEDULER_ENABLED)
        scheduler_interval_seconds = env_int("SCHEDULER_INTERVAL_SECONDS", DEFAULT_SCHEDULER_INTERVAL_SECONDS)
        scheduler_max_instances = env_int("SCHEDULER_MAX_INSTANCES", DEFAULT_SCHEDULER_MAX_INSTANCES)
        scheduler_coalesce = env_bool("SCHEDULER_COALESCE", DEFAULT_SCHEDULER_COALESCE)
        scheduler_misfire_grace_seconds = env_int("SCHEDULER_MISFIRE_GRACE_SECONDS", DEFAULT_SCHEDULER_MISFIRE_GRACE_SECONDS)

        max_unlock_per_run = env_int("MAX_UNLOCK_PER_RUN", DEFAULT_MAX_UNLOCK_PER_RUN)

        return cls(
            app_version=app_version,
            flask_secret_key=flask_secret_key,
            cors_origins=cors_origins,
            log_level=log_level,
            noisy_paths=noisy_paths,
            admin_enabled=admin_enabled,
            admin_ui_enabled=admin_ui_enabled,
            admin_user=admin_user,
            admin_pass=admin_pass,
            admin_realm=admin_realm,
            alldebrid_base_url=alldebrid_base_url,
            alldebrid_apikey=alldebrid_apikey,
            alldebrid_timeout=alldebrid_timeout,
            ad_ping_path=ad_ping_path,
            ad_endpoints=ad_endpoints,
            redis_host=redis_host,
            redis_port=redis_port,
            redis_db=redis_db,
            synology_url=synology_url,
            synology_user=synology_user,
            synology_password=synology_password,
            dsm_login_timeout=dsm_login_timeout,
            dsm_task_timeout=dsm_task_timeout,
            dsm_logout_timeout=dsm_logout_timeout,
            nas_enabled=nas_enabled,
            status_route_enabled=status_route_enabled,
            status_http_timeout=status_http_timeout,
            status_dsm_timeout=status_dsm_timeout,
            premium_green_days=premium_green_days,
            premium_yellow_days=premium_yellow_days,
            scheduler_enabled=scheduler_enabled,
            scheduler_interval_seconds=scheduler_interval_seconds,
            scheduler_max_instances=scheduler_max_instances,
            scheduler_coalesce=scheduler_coalesce,
            scheduler_misfire_grace_seconds=scheduler_misfire_grace_seconds,
            max_unlock_per_run=max_unlock_per_run,
        )


def load_settings() -> Settings:
    return Settings.from_env()