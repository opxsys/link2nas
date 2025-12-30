from __future__ import annotations

import requests

from .config import Settings
from .redis_store import NAS_ERROR_NO_LINKS, NAS_ERROR_NAS_DISABLED


def send_to_download_station(s: Settings, links: list[str]) -> bool:
    if not s.nas_enabled:
        return False

    links = [str(x).strip() for x in (links or []) if str(x).strip()]
    if not links:
        return False

    if not s.synology_url or not s.synology_user or not s.synology_password:
        return False

    login_url = f"{s.synology_url}/webapi/auth.cgi"
    task_url = f"{s.synology_url}/webapi/DownloadStation/task.cgi"
    logout_url = f"{s.synology_url}/webapi/auth.cgi"

    http = requests.Session()
    sid = None
    success_count = 0

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
            timeout=s.dsm_login_timeout,
        )
        r.raise_for_status()
        js = r.json()

        if not js.get("success"):
            return False

        sid = (js.get("data") or {}).get("sid")
        if not sid:
            return False

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
            )
            tr.raise_for_status()
            tj = tr.json()
            if tj.get("success"):
                success_count += 1

        return success_count > 0

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
                    timeout=s.dsm_logout_timeout,
                )
            except Exception:
                pass
        try:
            http.close()
        except Exception:
            pass

def synology_ping_safe(timeout: int = 6) -> dict:
    """
    Ping minimal DSM : login puis logout.
    - Pas de création de tâche (aucun side effect)
    """
    if not NAS_ENABLED:
        return {"enabled": False, "ok": None, "message": "NAS disabled"}

    base = str(os.getenv("SYNOLOGY_URL", "")).strip().rstrip("/")
    if not base:
        return {"enabled": True, "ok": False, "message": "SYNOLOGY_URL missing"}

    login_url = f"{base}/webapi/auth.cgi"
    logout_url = f"{base}/webapi/auth.cgi"

    http = requests.Session()
    sid = None
    try:
        r = http.post(
            login_url,
            data={
                "api": "SYNO.API.Auth",
                "version": "3",
                "method": "login",
                "account": os.getenv("SYNOLOGY_USER", ""),
                "passwd": os.getenv("SYNOLOGY_PASSWORD", ""),
                "session": "DownloadStation",
                "format": "sid",
            },
            timeout=timeout,
        )
        r.raise_for_status()
        js = r.json()
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
                )
            except Exception:
                pass
        try:
            http.close()
        except Exception:
            pass


def send_to_download_station_safe(s: Settings, links: list[str]) -> tuple[bool, dict]:
    links = [str(x).strip() for x in (links or []) if str(x).strip()]
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