# link2nas/synology.py
from __future__ import annotations

import os
from typing import Any

import requests

from .config import Settings
from .redis_store import NAS_ERROR_NO_LINKS, NAS_ERROR_NAS_DISABLED


# ==================================================
# Config helpers (env overrides)
# ==================================================
def _env_bool(name: str, default: bool = False) -> bool:
    """
    Lit un bool depuis l'environnement.
    Valeurs true:  1,true,yes,y,on
    Valeurs false: 0,false,no,n,off
    Sinon: default
    """
    v = str(os.getenv(name, "")).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _sanitize_links(links: list[str] | None) -> list[str]:
    """Nettoie la liste de liens (strip + drop vides)."""
    return [str(x).strip() for x in (links or []) if str(x).strip()]


def _dsm_urls(base: str) -> tuple[str, str, str]:
    """
    Construit les URLs DSM utilisées ici.
    - auth.cgi  : login/logout
    - task.cgi  : création tâches DownloadStation
    """
    b = (base or "").strip().rstrip("/")
    login_url = f"{b}/webapi/auth.cgi"
    task_url = f"{b}/webapi/DownloadStation/task.cgi"
    logout_url = f"{b}/webapi/auth.cgi"
    return login_url, task_url, logout_url


# ==================================================
# Core DSM calls (DownloadStation)
# ==================================================
def send_to_download_station(s: Settings, links: list[str]) -> bool:
    """
    Legacy/simple DS create.
    - Login DSM (session DownloadStation)
    - Create task(s) (sans destination)
    - Logout DSM
    Retourne True si au moins 1 création a réussi.

    Note: conservée pour compatibilité (appelée par le wrapper *_safe).
    """
    if not s.nas_enabled:
        return False

    links = _sanitize_links(links)
    if not links:
        return False

    if not s.synology_url or not s.synology_user or not s.synology_password:
        return False

    # Env override: permet de forcer la vérif SSL sans modifier Settings.
    verify_ssl = _env_bool("SYNOLOGY_VERIFY_SSL", True)

    login_url, task_url, logout_url = _dsm_urls(s.synology_url)

    http = requests.Session()
    sid: str | None = None
    success_count = 0

    try:
        # 1) Login DSM
        r = http.post(
            login_url,
            data={
                "api": "SYNO.API.Auth",
                "version": "3",
                "method": "login",
                "account": s.synology_user,
                "passwd": s.synology_password,
                "session": "DownloadStation",
                "format": "sid",
            },
            timeout=s.dsm_login_timeout,
            verify=verify_ssl,
        )
        r.raise_for_status()
        js: dict[str, Any] = r.json()

        if not js.get("success"):
            return False

        sid = (js.get("data") or {}).get("sid")
        if not sid:
            return False

        # 2) Create tasks
        for link in links:
            tr = http.post(
                task_url,
                data={
                    "api": "SYNO.DownloadStation.Task",
                    "version": "1",
                    "method": "create",
                    "uri": link,
                    "_sid": sid,
                },
                timeout=s.dsm_task_timeout,
                verify=verify_ssl,
            )
            tr.raise_for_status()
            tj: dict[str, Any] = tr.json()
            if tj.get("success"):
                success_count += 1

        return success_count > 0

    finally:
        # 3) Logout DSM (best-effort)
        if sid:
            try:
                http.post(
                    logout_url,
                    data={
                        "api": "SYNO.API.Auth",
                        "version": "3",
                        "method": "logout",
                        "session": "DownloadStation",
                        "_sid": sid,
                    },
                    timeout=s.dsm_logout_timeout,
                    verify=verify_ssl,
                )
            except Exception:
                pass

        try:
            http.close()
        except Exception:
            pass


# ==================================================
# Public: status/ping (no side effects)
# ==================================================
def synology_ping_safe(s: Settings, timeout: int = 6) -> dict:
    """
    Ping DSM minimal: login puis logout.
    - Aucun side effect (pas de création de tâche)
    - Utilisé par status.py (import synology_ping_safe depuis link2nas.synology)
    """
    if not s.nas_enabled:
        return {"enabled": False, "ok": None, "message": "NAS disabled"}

    base = (s.synology_url or "").strip().rstrip("/")
    if not base:
        return {"enabled": True, "ok": False, "message": "SYNOLOGY_URL missing"}

    if not (s.synology_user and s.synology_password):
        return {"enabled": True, "ok": False, "message": "SYNOLOGY credentials missing"}

    verify_ssl = _env_bool("SYNOLOGY_VERIFY_SSL", True)

    login_url, _, logout_url = _dsm_urls(base)

    http = requests.Session()
    sid: str | None = None
    try:
        r = http.post(
            login_url,
            data={
                "api": "SYNO.API.Auth",
                "version": "3",
                "method": "login",
                "account": s.synology_user,
                "passwd": s.synology_password,
                "session": "DownloadStation",
                "format": "sid",
            },
            timeout=timeout,
            verify=verify_ssl,
        )
        r.raise_for_status()
        js: dict[str, Any] = r.json()

        if not js.get("success"):
            code = (js.get("error") or {}).get("code")
            return {"enabled": True, "ok": False, "message": f"DSM login failed (code={code})"}

        sid = (js.get("data") or {}).get("sid")
        if not sid:
            return {"enabled": True, "ok": False, "message": "DSM login ok but SID missing"}

        return {"enabled": True, "ok": True, "message": "DSM OK"}

    except requests.exceptions.Timeout:
        return {"enabled": True, "ok": False, "message": "DSM timeout"}
    except Exception as e:
        return {"enabled": True, "ok": False, "message": str(e)}

    finally:
        if sid:
            try:
                http.post(
                    logout_url,
                    data={
                        "api": "SYNO.API.Auth",
                        "version": "3",
                        "method": "logout",
                        "session": "DownloadStation",
                        "_sid": sid,
                    },
                    timeout=timeout,
                    verify=verify_ssl,
                )
            except Exception:
                pass

        try:
            http.close()
        except Exception:
            pass


# ==================================================
# Public: wrapper safe (retours normalisés)
# ==================================================
def send_to_download_station_safe(s: Settings, links: list[str]) -> tuple[bool, dict]:
    """
    Wrapper “safe”:
    - valide inputs + config
    - renvoie (ok, payload_erreur_normalisé)
    """
    links = _sanitize_links(links)
    if not links:
        return False, {"kind": "nas_error", "code": NAS_ERROR_NO_LINKS, "message": "no_links"}

    if not s.nas_enabled:
        return False, {"kind": "nas_error", "code": NAS_ERROR_NAS_DISABLED, "message": "NAS disabled by configuration"}

    if not s.synology_url or not s.synology_user or not s.synology_password:
        return False, {"kind": "nas_error", "code": "DSM_CONFIG_MISSING", "message": "Synology config missing"}

    try:
        ok = bool(send_to_download_station(s, links))
        if ok:
            return True, {}
        return False, {"kind": "nas_error", "code": "NAS_SEND_FAILED", "message": "send_failed"}

    except requests.exceptions.Timeout:
        return False, {"kind": "timeout", "code": "TIMEOUT", "message": "NAS timeout"}
    except requests.exceptions.RequestException as e:
        return False, {"kind": "network", "code": "NETWORK_ERROR", "message": str(e)}
    except Exception as e:
        return False, {"kind": "nas_error", "code": "NAS_EXCEPTION", "message": str(e)}
