import os
from pathlib import Path
from typing import Optional, Set

from dotenv import load_dotenv


load_dotenv()


def env(name: str, default: Optional[str] = None, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and (value is None or str(value).strip() == ""):
        raise ValueError(f"Missing required environment variable: {name}")
    return "" if value is None else str(value).strip()


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer") from exc


def env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be a float") from exc


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default

    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False

    raise ValueError(f"Environment variable {name} must be a boolean")


def env_csv(name: str, default: str = "") -> Set[str]:
    raw = os.getenv(name, default)
    return {item.strip() for item in raw.split(",") if item.strip()}


class Settings:
    def __init__(self) -> None:
        self.APP_NAME = env("APP_NAME", "link2nas")
        self.APP_TAGLINE = env("APP_TAGLINE", "Job management + debrid provider")
        self.APP_VERSION = env("APP_VERSION", "0.1.0")
        self.DEBUG = env_bool("DEBUG", False)
        self.V2_DEV_ROUTES_ENABLED = env_bool("V2_DEV_ROUTES_ENABLED", False)
        self.V2_RATE_LIMIT_ENABLED = env_bool("V2_RATE_LIMIT_ENABLED", True)
        self.REDIS_URL = env("REDIS_URL", "")

        self.V2_RATE_LIMIT_REDIS_REQUIRED = env_bool("V2_RATE_LIMIT_REDIS_REQUIRED", False)

        self.V2_RATE_LIMIT_LOGIN_MAX = env_int("V2_RATE_LIMIT_LOGIN_MAX", 10)
        self.V2_RATE_LIMIT_LOGIN_WINDOW_SECONDS = env_int("V2_RATE_LIMIT_LOGIN_WINDOW_SECONDS", 300)

        self.V2_RATE_LIMIT_MAGIC_LOGIN_MAX = env_int("V2_RATE_LIMIT_MAGIC_LOGIN_MAX", 5)
        self.V2_RATE_LIMIT_MAGIC_LOGIN_WINDOW_SECONDS = env_int("V2_RATE_LIMIT_MAGIC_LOGIN_WINDOW_SECONDS", 3600)

        self.V2_RATE_LIMIT_TOKEN_STATUS_MAX = env_int("V2_RATE_LIMIT_TOKEN_STATUS_MAX", 60)
        self.V2_RATE_LIMIT_TOKEN_STATUS_WINDOW_SECONDS = env_int("V2_RATE_LIMIT_TOKEN_STATUS_WINDOW_SECONDS", 300)

        self.V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX = env_int("V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX", 20)
        self.V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS = env_int("V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS", 300)

        self.V2_RATE_LIMIT_EMAIL_REQUEST_MAX = env_int("V2_RATE_LIMIT_EMAIL_REQUEST_MAX", 5)
        self.V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS = env_int("V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS", 3600)

        self.V2_RATE_LIMIT_QBITTORRENT_ADD_MAX = env_int("V2_RATE_LIMIT_QBITTORRENT_ADD_MAX", 30)
        self.V2_RATE_LIMIT_QBITTORRENT_ADD_WINDOW_SECONDS = env_int("V2_RATE_LIMIT_QBITTORRENT_ADD_WINDOW_SECONDS", 60)

        self.HOST = env("HOST", "0.0.0.0")
        self.PORT = env_int("PORT", 5000)
        self.LOG_LEVEL = env("LOG_LEVEL", "INFO")
        self.LOG_KNOWN_ERRORS_TRACEBACK = env_bool("LOG_KNOWN_ERRORS_TRACEBACK", False)

        self.BASE_DIR = Path(env("BASE_DIR", ".")).resolve()
        self.DATA_DIR = Path(env("DATA_DIR", "./data")).resolve()
        self.USERDATA_DIR = Path(
            env("USERDATA_DIR", str(self.DATA_DIR / "userdata"))
        ).resolve()
        self.TORRENT_DIR = Path(
            env("TORRENT_DIR", str(self.DATA_DIR / "torrents"))
        ).resolve()        
        self.TEMP_DIR = Path(env("TEMP_DIR", "./tmp/link2nas")).resolve()
        self.LOG_DIR = Path(env("LOG_DIR", "./logs")).resolve()
        self.FLASK_SECRET_KEY = env("FLASK_SECRET_KEY", "change-me")
        self.PUBLIC_BASE_URL = env("PUBLIC_BASE_URL", "").rstrip("/")
        self.LINK2NAS_SINGLE_USER_MODE = env_bool("LINK2NAS_SINGLE_USER_MODE", False)
        self.LINK2NAS_SINGLE_USER_EMAIL = env(
            "LINK2NAS_SINGLE_USER_EMAIL",
            "single-user@link2nas.local",
        ).lower()
        self.LINK2NAS_SINGLE_USER_DISPLAY_NAME = env(
            "LINK2NAS_SINGLE_USER_DISPLAY_NAME",
            "Single User",
        )
        self.V2_SECRET_ENCRYPTION_KEY = env("V2_SECRET_ENCRYPTION_KEY", required=not self.DEBUG)
        self.V2_DATABASE_BACKEND = env("V2_DATABASE_BACKEND", "sqlite").lower()
        self.V2_SQLITE_PATH = Path(
            env("V2_SQLITE_PATH", str(self.DATA_DIR / "link2nas_v2.sqlite3"))
        ).resolve()
        self.V2_SCHEMA_PATH = Path(
            env("V2_SCHEMA_PATH", str(self.BASE_DIR / "backend" / "storage" / "schema.sql"))
        ).resolve()
        self.V2_POSTGRES_DSN = env("V2_POSTGRES_DSN", "")
        self.V2_POSTGRES_SCHEMA_PATH = Path(
            env(
                "V2_POSTGRES_SCHEMA_PATH",
                str(self.BASE_DIR / "backend" / "storage" / "schema_postgres.sql")
            )
        ).resolve()
        if self.V2_DATABASE_BACKEND == "postgres" and not self.V2_POSTGRES_DSN:
            raise ValueError("V2_POSTGRES_DSN is required when V2_DATABASE_BACKEND=postgres")

        if not self.DEBUG:
            self._validate_production_secrets()
        self.CORS_ENABLED = env_bool("CORS_ENABLED", False)
        self.CORS_ORIGINS = env_csv("CORS_ORIGINS", "")
        self.REDIS_HOST = env("REDIS_HOST", "127.0.0.1")
        self.REDIS_PORT = env_int("REDIS_PORT", 6379)
        self.REDIS_DB = env_int("REDIS_DB", 0)
        self.RQ_QUEUE_NAME = env("RQ_QUEUE_NAME", "link2nas")
        self.RQ_LOCAL_DOWNLOAD_QUEUE_NAME = env("RQ_LOCAL_DOWNLOAD_QUEUE_NAME", "link2nas-local-downloads")
        self.LOCAL_DOWNLOAD_SPACE_MARGIN_PERCENT = env_int("LOCAL_DOWNLOAD_SPACE_MARGIN_PERCENT", 10)
        self.LOCAL_DOWNLOAD_MIN_FREE_BYTES = env_int("LOCAL_DOWNLOAD_MIN_FREE_BYTES", 1024 * 1024 * 1024)

        self.REALDEBRID_BASE_URL = env("REALDEBRID_BASE_URL", "https://api.real-debrid.com/rest/1.0")
        self.REALDEBRID_TIMEOUT = env_float("REALDEBRID_TIMEOUT", 30.0)

        self.ALLDEBRID_BASE_URL = env("ALLDEBRID_BASE_URL", "https://api.alldebrid.com")
        self.ALLDEBRID_TIMEOUT = env_float("ALLDEBRID_TIMEOUT", 30.0)

        self.RESTART_COOLDOWN_SECONDS_DEFAULT = env_int("RESTART_COOLDOWN_SECONDS_DEFAULT", 10)
        self.RESTART_COOLDOWN_SECONDS_REALDEBRID = env_int("RESTART_COOLDOWN_SECONDS_REALDEBRID", 20)
        self.RESTART_COOLDOWN_SECONDS_ALLDEBRID = env_int("RESTART_COOLDOWN_SECONDS_ALLDEBRID", 8)

        self.CLEANUP_ENABLED = env_bool("CLEANUP_ENABLED", True)
        self.CLEANUP_COMPLETED_JOB_RETENTION_HOURS = env_int("CLEANUP_COMPLETED_JOB_RETENTION_HOURS", 168)
        self.CLEANUP_FAILED_JOB_RETENTION_HOURS = env_int("CLEANUP_FAILED_JOB_RETENTION_HOURS", 336)
        self.CLEANUP_CANCELLED_JOB_RETENTION_HOURS = env_int("CLEANUP_CANCELLED_JOB_RETENTION_HOURS", 336)
        self.CLEANUP_TEMP_FILE_RETENTION_HOURS = env_int("CLEANUP_TEMP_FILE_RETENTION_HOURS", 24)

    def _validate_production_secrets(self) -> None:
        _PLACEHOLDERS = frozenset({
            "change-me", "change_me", "changeme",
            "CHANGE_ME_long_random_string",
            "CHANGE_ME_32_hex_bytes",
            "CHANGE_ME_fernet_key",
            "secret", "password", "default",
        })

        flask_key = self.FLASK_SECRET_KEY
        if not flask_key or flask_key in _PLACEHOLDERS or len(flask_key) < 20:
            raise ValueError(
                "FLASK_SECRET_KEY is missing, a placeholder, or too short (min 20 chars). "
                "Set a strong random value in production."
            )

        enc_key = self.V2_SECRET_ENCRYPTION_KEY
        if not enc_key or enc_key in _PLACEHOLDERS:
            raise ValueError(
                "V2_SECRET_ENCRYPTION_KEY is missing or a placeholder. "
                'Generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )

        try:
            from cryptography.fernet import Fernet as _Fernet
            _Fernet(enc_key.encode())
        except Exception:
            raise ValueError(
                "V2_SECRET_ENCRYPTION_KEY is not a valid Fernet key. "
                'Generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )

    def ensure_directories(self) -> None:
        for directory in (
            self.DATA_DIR,
            self.USERDATA_DIR,
            self.TEMP_DIR,
            self.LOG_DIR,
        ):
            directory.mkdir(parents=True, exist_ok=True)
