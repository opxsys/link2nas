# link2nas/config.py
from __future__ import annotations

import os
from dataclasses import dataclass

# ==============================================================================
# Env parsing helpers
# - Keep these tiny and predictable.
# - No logging here.
# - "Required" env vars are enforced only inside Settings.from_env().
# ==============================================================================

try:
    from ._version import __version__ as APP_VERSION
except Exception:
    APP_VERSION = "dev"


def env_str(name: str, default: str | None = None) -> str:
    """
    Read an env var as string.
    - If default is None: var is REQUIRED (raises if missing/empty).
    - Else: returns default when missing/empty.
    """
    v = os.getenv(name)
    if v is None or str(v).strip() == "":
        if default is None:
            raise RuntimeError(f"Missing required env var: {name}")
        return default
    return str(v)


def env_int(name: str, default: int) -> int:
    """Read an env var as int, fallback to default on missing/invalid."""
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    """Read an env var as bool (1/true/yes/on ; 0/false/no/off)."""
    v = str(os.getenv(name, "")).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def env_csv(name: str, default: str = "") -> str:
    """
    Read a CSV env var and normalize it:
    - empty => ""
    - "*" => "*"
    - otherwise: trims items and joins with comma
    """
    raw = str(os.getenv(name, default) or "").strip()
    if not raw:
        return ""
    if raw == "*":
        return "*"
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return ",".join(parts)


def env_set_csv(name: str, default: set[str]) -> set[str]:
    """Read a CSV env var into a set[str]."""
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return set(default)
    return {p.strip() for p in raw.split(",") if p.strip()}


def has_synology_config(url: str, user: str, password: str) -> bool:
    """True if Synology connection settings are present (non-empty)."""
    return bool(str(url or "").strip() and str(user or "").strip() and str(password or "").strip())


def normalize_dsm_path(path: str, default: str) -> str:
    """Normalize a DSM absolute path (FileStation)."""
    p = str(path or "").strip()
    if not p:
        p = default
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or default


def normalize_ds_destination(dest: str, default: str) -> str:
    """Normalize a DownloadStation destination (relative)."""
    d = str(dest or "").strip().strip("/")
    return d or default


# ==============================================================================
# Module defaults (pure constants; do not read env here)
# ==============================================================================

DEFAULT_APP_VERSION = "dev"
DEFAULT_LOG_LEVEL = "INFO"

DEFAULT_NOISY_PATHS = {
    "/api/pending_torrents",
    "/api/completed_torrents",
}

DEFAULT_ADMIN_ENABLED = True
DEFAULT_ADMIN_UI_ENABLED = True
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_REALM = "Link2NAS Admin"

DEFAULT_REDIS_HOST = "localhost"
DEFAULT_REDIS_PORT = 6379
DEFAULT_REDIS_DB = 0

DEFAULT_ALLDEBRID_TIMEOUT = 60
DEFAULT_ALLDEBRID_FOLLOW_REDIRECTS = True
DEFAULT_ALLDEBRID_REDIRECTOR_CACHE_TTL = 86400

DEFAULT_DSM_LOGIN_TIMEOUT = 10
DEFAULT_DSM_TASK_TIMEOUT = 30
DEFAULT_DSM_LOGOUT_TIMEOUT = 5

DEFAULT_NAS_ENABLED = True
DEFAULT_FILESTATION_BASE_PATH = "/downloads"
DEFAULT_DSM_DESTINATION_BASE = "downloads"

DEFAULT_STATUS_ROUTE_ENABLED = True
DEFAULT_STATUS_HTTP_TIMEOUT = 6
DEFAULT_STATUS_DSM_TIMEOUT = 6

DEFAULT_PREMIUM_GREEN_DAYS = 14
DEFAULT_PREMIUM_YELLOW_DAYS = 7

DEFAULT_SCHEDULER_ENABLED = False
DEFAULT_SCHEDULER_INTERVAL_SECONDS = 10
DEFAULT_SCHEDULER_MAX_INSTANCES = 1
DEFAULT_SCHEDULER_COALESCE = True
DEFAULT_SCHEDULER_MISFIRE_GRACE_SECONDS = 30
DEFAULT_MAX_UNLOCK_PER_RUN = 30


# ==============================================================================
# Settings object used by create_app()
# ==============================================================================


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
    # - admin_enabled: enables protection + admin endpoints (basic auth).
    # - admin_ui_enabled: controls UI affordances (buttons/sections).
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
    alldebrid_follow_redirects: bool
    alldebrid_redirector_cache_ttl: int

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
    filestation_base_path: str
    dsm_destination_base: str

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
        # ------------------------------
        # Core app (secret is REQUIRED)
        # ------------------------------
        app_version = APP_VERSION
        flask_secret_key = env_str("FLASK_SECRET_KEY", None)

        log_level = env_str("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper().strip() or DEFAULT_LOG_LEVEL
        cors_origins = env_csv("CORS_ORIGINS", "")
        noisy_paths = env_set_csv("NOISY_PATHS", DEFAULT_NOISY_PATHS)

        # ------------------------------
        # Admin / Basic auth
        # ------------------------------
        admin_enabled = env_bool("ADMIN_ENABLED", DEFAULT_ADMIN_ENABLED)
        admin_ui_enabled = env_bool("ADMIN_UI_ENABLED", DEFAULT_ADMIN_UI_ENABLED)

        admin_user = env_str("ADMIN_USER", DEFAULT_ADMIN_USER)
        admin_pass = env_str("ADMIN_PASS", "")  # required only if admin_enabled
        admin_realm = env_str("ADMIN_REALM", DEFAULT_ADMIN_REALM)

        if admin_enabled and not admin_pass.strip():
            raise RuntimeError("ADMIN_ENABLED=1 but ADMIN_PASS is empty")

        # ------------------------------
        # Redis
        # ------------------------------
        redis_host = env_str("REDIS_HOST", DEFAULT_REDIS_HOST)
        redis_port = env_int("REDIS_PORT", DEFAULT_REDIS_PORT)
        redis_db = env_int("REDIS_DB", DEFAULT_REDIS_DB)

        # ------------------------------
        # AllDebrid (REQUIRED)
        # ------------------------------
        alldebrid_apikey = env_str("ALLDEBRID_APIKEY", None)
        alldebrid_base_url = env_str("ALLDEBRID_BASE_URL", None)

        ad_endpoints = {
            "user": env_str("ALLDEBRID_API_USER", None),
            "magnet_upload": env_str("ALLDEBRID_API_MAGNET_UPLOAD", None),
            "magnet_status": env_str("ALLDEBRID_API_MAGNET_STATUS", None),
            "magnet_files": env_str("ALLDEBRID_API_MAGNET_FILES", None),
            "magnet_delete": env_str("ALLDEBRID_API_MAGNET_DELETE", None),
            "link_unlock": env_str("ALLDEBRID_API_LINK_UNLOCK", None),
            "hosts": env_str("ALLDEBRID_API_HOSTS", None),
            "link_redirector": env_str("ALLDEBRID_API_LINK_REDIRECTOR", None),
        }

        alldebrid_timeout = env_int("ALLDEBRID_TIMEOUT", DEFAULT_ALLDEBRID_TIMEOUT)
        ad_ping_path = env_str("ALLDEBRID_API_PING", "/v4/ping")
        alldebrid_follow_redirects = env_bool("ALLDEBRID_FOLLOW_REDIRECTS", DEFAULT_ALLDEBRID_FOLLOW_REDIRECTS)
        alldebrid_redirector_cache_ttl = env_int(
            "ALLDEBRID_REDIRECTOR_CACHE_TTL", DEFAULT_ALLDEBRID_REDIRECTOR_CACHE_TTL
        )

        # ------------------------------
        # NAS / Synology (optional)
        # Note: nas_enabled requires both NAS_ENABLED=1 and synology config present.
        # ------------------------------
        # ============================================================
        # Synology / NAS — Documentation & conventions
        # ============================================================
        #
        # Champs Settings concernés :
        #
        #   synology_url: str
        #   synology_user: str
        #   synology_password: str
        #   dsm_login_timeout: int
        #   dsm_task_timeout: int
        #   dsm_logout_timeout: int
        #   nas_enabled: bool
        #   filestation_base_path: str
        #   dsm_destination_base: str
        #
        #
        # --- RÔLES DES CHAMPS (IMPORTANT) ---
        #
        # synology_url
        #   URL de base du DSM, SANS slash final.
        #   Exemples :
        #     - https://nas.mondomaine.local
        #     - https://192.168.1.10:5001
        #
        # synology_user / synology_password
        #   Compte DSM autorisé à :
        #     - créer des dossiers (FileStation)
        #     - créer des tâches DownloadStation
        #
        # nas_enabled
        #   Active/désactive TOUTE la logique NAS.
        #   - False  → aucun appel DSM (scheduler et web ignorent le NAS)
        #   - True   → DSM utilisé si la config est valide
        #
        #
        # --- TIMEOUTS ---
        #
        # dsm_login_timeout
        #   Timeout (s) pour login DSM + API.Info
        #   Valeur recommandée : 6–10
        #
        # dsm_task_timeout
        #   Timeout (s) pour :
        #     - mkdir FileStation
        #     - task/create DownloadStation
        #   Valeur recommandée : 10–30
        #
        # dsm_logout_timeout
        #   Timeout (s) pour logout DSM (best-effort)
        #   Valeur recommandée : 3–6
        #
        #
        # --- CHEMINS : POINT CRITIQUE ---
        #
        # filestation_base_path
        #   Chemin RÉEL FileStation (filesystem DSM).
        #   Utilisé UNIQUEMENT pour :
        #     - créer les dossiers via FileStation
        #
        #   Doit être un chemin ABSOLU valide DSM.
        #
        #   Exemples CORRECTS :
        #     "/volume1/downloads"
        #     "/volume2/media"
        #
        #   Exemples MAUVAIS :
        #     "downloads"
        #     "/downloads"
        #
        #
        # dsm_destination_base
        #   Base "destination" DownloadStation.
        #   Utilisée pour task/create (où DownloadStation va écrire).
        #
        #   DSM est incohérent selon versions → on teste plusieurs formats :
        #     - relatif      : "downloads/mon-dossier"
        #     - pseudo-absolu: "/downloads/mon-dossier"
        #     - folder-only  : "mon-dossier"
        #
        #   Bonnes valeurs typiques :
        #     - "downloads"
        #     - "/downloads"
        #
        #   À NE PAS mettre :
        #     - "/volume1/downloads"  (souvent refusé par DownloadStation)
        #
        #
        # --- MAPPING CONSEILLÉ (LE PLUS STABLE) ---
        #
        #   filestation_base_path = "/volume1/downloads"
        #   dsm_destination_base  = "downloads"
        #
        #   Résultat :
        #     - FileStation crée : /volume1/downloads/<folder>
        #     - DownloadStation écrit dans : downloads/<folder>
        #
        #
        # --- VARIABLES D’ENV DSM (optionnelles) ---
        #
        # SYNOLOGY_VERIFY_SSL=true|false
        #   false = autorisé uniquement en LAN / cert foireux (WARNING loggé)
        #
        # DSM_AUTH_METHOD=GET|POST
        #   Méthode HTTP pour login/logout DSM
        #   (GET par défaut, POST recommandé si supporté)
        #
        # DSM_DS_METHOD=GET|POST
        #   Méthode HTTP pour DownloadStation task/create
        #   RECOMMANDÉ : POST (évite d’exposer l’URI dans l’URL)
        #
        # DSM_FS_METHOD=GET|POST
        #   Méthode HTTP pour FileStation mkdir
        #
        # DSM_ENABLE_SYNO_TOKEN=true|false
        #   Active la récupération du SynoToken
        #
        # DSM_REQUIRE_SYNO_TOKEN=true|false
        #   Si true → échec du login si le token n’est pas fourni
        #
        #
        # --- RÈGLES DE SÉCURITÉ ---
        #
        # - Ne JAMAIS logger :
        #     synology_password, sid, synotoken, uri complets
        # - Les erreurs DSM sont encapsulées dans SynologyApiError
        #   avec payload minimal (safe pour UI/logs)
        #
        #
        # --- DÉPANNAGE RAPIDE ---
        #
        # - Erreurs 101 / 105 / 403 en DownloadStation :
        #     → destination invalide ou non autorisée
        #     → vérifier dsm_destination_base
        #
        # - mkdir OK mais task/create KO :
        #     → filestation_base_path OK
        #     → dsm_destination_base MAUVAIS
        #
        # - task/create OK sans destination :
        #     → DownloadStation utilise son dossier par défaut
        #
        # ============================================================
        synology_url = env_str("SYNOLOGY_URL", "").strip().rstrip("/")
        synology_user = env_str("SYNOLOGY_USER", "").strip()
        synology_password = env_str("SYNOLOGY_PASSWORD", "").strip()

        dsm_login_timeout = env_int("DSM_LOGIN_TIMEOUT", DEFAULT_DSM_LOGIN_TIMEOUT)
        dsm_task_timeout = env_int("DSM_TASK_TIMEOUT", DEFAULT_DSM_TASK_TIMEOUT)
        dsm_logout_timeout = env_int("DSM_LOGOUT_TIMEOUT", DEFAULT_DSM_LOGOUT_TIMEOUT)

        nas_flag = env_bool("NAS_ENABLED", DEFAULT_NAS_ENABLED)
        nas_enabled = bool(nas_flag and has_synology_config(synology_url, synology_user, synology_password))

        filestation_base_path = normalize_dsm_path(env_str("FILESTATION_BASE_PATH", DEFAULT_FILESTATION_BASE_PATH), DEFAULT_FILESTATION_BASE_PATH)
        dsm_destination_base = normalize_ds_destination(env_str("DSM_DESTINATION_BASE", DEFAULT_DSM_DESTINATION_BASE), DEFAULT_DSM_DESTINATION_BASE)

        # ------------------------------
        # Status / health endpoints
        # ------------------------------
        status_route_enabled = env_bool("STATUS_ROUTE_ENABLED", DEFAULT_STATUS_ROUTE_ENABLED)
        status_http_timeout = env_int("STATUS_HTTP_TIMEOUT", DEFAULT_STATUS_HTTP_TIMEOUT)
        status_dsm_timeout = env_int("STATUS_DSM_TIMEOUT", DEFAULT_STATUS_DSM_TIMEOUT)

        premium_green_days = env_int("PREMIUM_GREEN_DAYS", DEFAULT_PREMIUM_GREEN_DAYS)
        premium_yellow_days = env_int("PREMIUM_YELLOW_DAYS", DEFAULT_PREMIUM_YELLOW_DAYS)

        # ------------------------------
        # Scheduler
        # ------------------------------
        scheduler_enabled = env_bool("SCHEDULER_ENABLED", DEFAULT_SCHEDULER_ENABLED)
        scheduler_interval_seconds = env_int("SCHEDULER_INTERVAL_SECONDS", DEFAULT_SCHEDULER_INTERVAL_SECONDS)
        scheduler_max_instances = env_int("SCHEDULER_MAX_INSTANCES", DEFAULT_SCHEDULER_MAX_INSTANCES)
        scheduler_coalesce = env_bool("SCHEDULER_COALESCE", DEFAULT_SCHEDULER_COALESCE)
        scheduler_misfire_grace_seconds = env_int("SCHEDULER_MISFIRE_GRACE_SECONDS", DEFAULT_SCHEDULER_MISFIRE_GRACE_SECONDS)

        max_unlock_per_run = env_int("MAX_UNLOCK_PER_RUN", DEFAULT_MAX_UNLOCK_PER_RUN)

        return cls(
            # App
            app_version=app_version,
            flask_secret_key=flask_secret_key,
            # CORS / Logging
            cors_origins=cors_origins,
            log_level=log_level,
            noisy_paths=noisy_paths,
            # Admin
            admin_enabled=admin_enabled,
            admin_ui_enabled=admin_ui_enabled,
            admin_user=admin_user,
            admin_pass=admin_pass,
            admin_realm=admin_realm,
            # AllDebrid
            alldebrid_base_url=alldebrid_base_url,
            alldebrid_apikey=alldebrid_apikey,
            alldebrid_timeout=alldebrid_timeout,
            ad_ping_path=ad_ping_path,
            ad_endpoints=ad_endpoints,
            alldebrid_follow_redirects=alldebrid_follow_redirects,
            alldebrid_redirector_cache_ttl=alldebrid_redirector_cache_ttl,
            # Redis
            redis_host=redis_host,
            redis_port=redis_port,
            redis_db=redis_db,
            # NAS
            synology_url=synology_url,
            synology_user=synology_user,
            synology_password=synology_password,
            dsm_login_timeout=dsm_login_timeout,
            dsm_task_timeout=dsm_task_timeout,
            dsm_logout_timeout=dsm_logout_timeout,
            nas_enabled=nas_enabled,
            filestation_base_path=filestation_base_path,
            dsm_destination_base=dsm_destination_base,
            # Status
            status_route_enabled=status_route_enabled,
            status_http_timeout=status_http_timeout,
            status_dsm_timeout=status_dsm_timeout,
            premium_green_days=premium_green_days,
            premium_yellow_days=premium_yellow_days,
            # Scheduler
            scheduler_enabled=scheduler_enabled,
            scheduler_interval_seconds=scheduler_interval_seconds,
            scheduler_max_instances=scheduler_max_instances,
            scheduler_coalesce=scheduler_coalesce,
            scheduler_misfire_grace_seconds=scheduler_misfire_grace_seconds,
            max_unlock_per_run=max_unlock_per_run,
        )


def load_settings() -> Settings:
    """Convenience wrapper used by the app factory."""
    return Settings.from_env()
