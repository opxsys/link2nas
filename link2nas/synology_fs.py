# link2nas/synology_fs.py
from __future__ import annotations

"""
Synology DSM WebAPI helpers (Auth / FileStation / DownloadStation).

Objectifs
- Isoler toute la plomberie DSM dans un module unique.
- Standardiser les timeouts, la vérification SSL, le parsing JSON.
- Avoir une erreur typée (SynologyApiError) "safe" pour logs / UI (pas de fuite de secrets).
- Gérer les quirks DSM :
  - Beaucoup d'endpoints renvoient HTTP 200 même en erreur.
  - Certains NAS acceptent GET, d'autres préfèrent POST (on supporte les deux via Settings/env).
  - Le paramètre DownloadStation "destination" est très sensible (formats possibles).

Convention sécurité
- Ne jamais logger/retourner : password, sid, synotoken, uri complets, payload JSON complet.
- Les erreurs gardent : api, http_status, code, message, + mini resp safe.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Iterable

import requests

from .config import Settings

logger = logging.getLogger("link2nas.synology")


# ============================================================
# Errors
# ============================================================

class SynologyApiError(RuntimeError):
    """
    Exception typée pour erreurs DSM.
    - api: nom de l'API DSM (ex: SYNO.API.Auth.login)
    - code: code DSM (dans error.code) si présent
    - http_status: status HTTP si utile
    - resp: payload "safe" (minimal) pour debug sans fuite
    """
    __slots__ = ("api", "code", "http_status", "resp")

    def __init__(
        self,
        api: str,
        code: int | None,
        http_status: int | None,
        message: str,
        *,
        resp: dict | None = None,
    ):
        super().__init__(message)
        self.api = str(api or "").strip() or "synology"
        self.code = int(code) if isinstance(code, int) else None
        self.http_status = int(http_status) if isinstance(http_status, int) else None
        self.resp = resp or {}

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "api": self.api,
            "code": self.code,
            "http_status": self.http_status,
            "message": str(self),
        }
        if self.resp:
            d["resp"] = self.resp
        return d

    def __str__(self) -> str:
        base = super().__str__()
        parts = [self.api]
        if self.http_status is not None:
            parts.append(f"http={self.http_status}")
        if self.code is not None:
            parts.append(f"code={self.code}")
        return f"{base} ({', '.join(parts)})"

    def __repr__(self) -> str:
        return (
            f"SynologyApiError(api={self.api!r}, code={self.code!r}, "
            f"http_status={self.http_status!r}, message={super().__str__()!r})"
        )


# ============================================================
# Small utilities (env + path)
# ============================================================

def _env_bool(name: str, default: bool = False) -> bool:
    v = str(os.getenv(name, "")).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _env_str(name: str, default: str) -> str:
    v = str(os.getenv(name, "")).strip()
    return v if v else default


def _verify_ssl() -> bool:
    """
    ATTENTION: désactiver verify SSL est dangereux.
    Autorisé pour LAN/cert foireux, mais on log un warning.
    """
    v = _env_bool("SYNOLOGY_VERIFY_SSL", True)
    if not v:
        logger.warning("[DSM] SSL verification is DISABLED (SYNOLOGY_VERIFY_SSL=false).")
    return v


def _dsm_url(base: str, path: str) -> str:
    base = (base or "").strip().rstrip("/")
    p = (path or "").strip().lstrip("/")
    # DSM WebAPI est sous /webapi/<path>
    return f"{base}/webapi/{p}"


def _norm_abs(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    p = "/" + p.lstrip("/")
    while "//" in p:
        p = p.replace("//", "/")
    return p


def _norm_rel(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    p = p.strip("/")
    while "//" in p:
        p = p.replace("//", "/")
    return p


def _safe_json(js: Any) -> dict | None:
    """Retourne un dict JSON si possible, sinon None."""
    return js if isinstance(js, dict) else None


def _extract_error_code(js: dict | None) -> int | None:
    if not isinstance(js, dict):
        return None
    err = js.get("error")
    if isinstance(err, dict) and isinstance(err.get("code"), int):
        return int(err["code"])
    return None


def _safe_resp_min(js: dict | None) -> dict:
    """
    Payload minimal pour logs/retours (pas de fuite).
    On garde seulement success + error.code si présent.
    """
    if not isinstance(js, dict):
        return {"success": False}
    out: dict[str, Any] = {"success": bool(js.get("success"))}
    err = js.get("error")
    if isinstance(err, dict) and "code" in err:
        out["error"] = {"code": err.get("code")}
    return out


# ============================================================
# HTTP client wrapper
# ============================================================

def _http_request(
    s: Settings,
    *,
    method: str,
    url: str,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int | float | None = None,
    api_name: str = "synology",
    session: requests.Session | None = None,
    allow_non_json: bool = False,
) -> tuple[int, dict | None]:
    """
    Enveloppe requests.*:
    - gère verify SSL
    - parse JSON
    - ne raise pas automatiquement (DSM renvoie 200 en erreur)
    Retourne (http_status, json_dict_or_none)
    """
    verify = _verify_ssl()
    http = session or requests

    try:
        r = http.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            timeout=timeout,
            verify=verify,
        )
    except requests.exceptions.Timeout:
        raise SynologyApiError(api_name, None, None, "DSM request timeout", resp={"success": False})
    except requests.exceptions.RequestException as e:
        raise SynologyApiError(api_name, None, None, f"DSM network error: {e}", resp={"success": False})

    status = int(getattr(r, "status_code", 0) or 0)

    js: dict | None = None
    if r.content:
        try:
            js = _safe_json(r.json())
        except Exception:
            js = None

    if (js is None) and (not allow_non_json) and (status >= 200 and status < 500):
        # DSM renvoie parfois HTML (login page / reverse proxy), on signale proprement.
        raise SynologyApiError(
            api_name,
            None,
            status,
            "DSM bad payload (non-JSON)",
            resp={"success": False, "http_status": status},
        )

    return status, js


# ============================================================
# DSM API.Info
# ============================================================

def dsm_get_api_info(s: Settings, *, session: requests.Session | None = None) -> dict[str, Any]:
    """
    Récupère les infos d'API DSM (paths + versions).
    On query uniquement ce dont on a besoin : Auth, CreateFolder, DownloadStation.Task.
    """
    base = (s.synology_url or "").rstrip("/")
    url = f"{base}/webapi/query.cgi"

    params = {
        "api": "SYNO.API.Info",
        "version": "1",
        "method": "query",
        "query": "SYNO.API.Auth,SYNO.FileStation.CreateFolder,SYNO.DownloadStation.Task",
    }

    http_status, js = _http_request(
        s,
        method="GET",
        url=url,
        params=params,
        timeout=getattr(s, "dsm_login_timeout", 8),
        api_name="SYNO.API.Info.query",
        session=session,
    )

    if http_status < 200 or http_status >= 300:
        raise SynologyApiError("SYNO.API.Info.query", None, http_status, "HTTP error", resp={"success": False})

    if not (js and js.get("success") and isinstance(js.get("data"), dict)):
        code = _extract_error_code(js)
        raise SynologyApiError(
            "SYNO.API.Info.query",
            code,
            http_status,
            "API.Info failed",
            resp=_safe_resp_min(js),
        )

    return js["data"]


# ============================================================
# Session model
# ============================================================

@dataclass(frozen=True, slots=True)
class DsmSession:
    sid: str
    synotoken: str = ""


# ============================================================
# Auth
# ============================================================

def dsm_login(s: Settings, api_info: dict[str, Any], *, session: requests.Session | None = None) -> DsmSession:
    """
    Login DSM, retourne SID (+ SynoToken si activé).

    Notes:
    - DSM accepte GET ou POST selon config. Ici: default GET, overridable par env DSM_AUTH_METHOD.
    - SynoToken peut être demandé via enable_syno_token=yes (env DSM_ENABLE_SYNO_TOKEN).
    """
    auth = api_info.get("SYNO.API.Auth") or {}
    path = str(auth.get("path") or "entry.cgi")
    url = _dsm_url(s.synology_url, path)

    auth_method = _env_str("DSM_AUTH_METHOD", "GET").upper()
    session_name = _env_str("DSM_SESSION_NAME", "DownloadStation")
    auth_version = _env_str("DSM_AUTH_VERSION", "6")
    enable_token = "yes" if _env_bool("DSM_ENABLE_SYNO_TOKEN", True) else "no"

    # DSM accepte souvent params en query. En POST, on met en data.
    payload = {
        "api": "SYNO.API.Auth",
        "version": auth_version,
        "method": "login",
        "account": getattr(s, "synology_user", "") or "",
        "passwd": getattr(s, "synology_password", "") or "",
        "session": session_name,
        "format": "sid",
        "enable_syno_token": enable_token,
    }

    http_status, js = _http_request(
        s,
        method=auth_method,
        url=url,
        params=(payload if auth_method == "GET" else None),
        data=(payload if auth_method != "GET" else None),
        timeout=getattr(s, "dsm_login_timeout", 8),
        api_name="SYNO.API.Auth.login",
        session=session,
    )

    if not (js and js.get("success")):
        code = _extract_error_code(js)
        raise SynologyApiError(
            "SYNO.API.Auth.login",
            code,
            http_status,
            "DSM login failed",
            resp=_safe_resp_min(js),
        )

    data = js.get("data") if isinstance(js, dict) else None
    data = data if isinstance(data, dict) else {}

    sid = str(data.get("sid") or "").strip()
    synotoken = str(data.get("synotoken") or data.get("SynoToken") or "").strip()

    if not sid:
        raise SynologyApiError(
            "SYNO.API.Auth.login",
            None,
            http_status,
            "DSM login failed: missing sid",
            resp=_safe_resp_min(js),
        )

    if _env_bool("DSM_REQUIRE_SYNO_TOKEN", False) and not synotoken:
        raise SynologyApiError(
            "SYNO.API.Auth.login",
            None,
            http_status,
            "DSM login failed: missing synotoken",
            resp=_safe_resp_min(js),
        )

    return DsmSession(sid=sid, synotoken=synotoken)


def dsm_logout(s: Settings, api_info: dict[str, Any], sess: DsmSession, *, session: requests.Session | None = None) -> None:
    """
    Logout DSM (best-effort).
    - Ne lève pas d'exception (on ne veut pas masquer l'erreur principale).
    """
    try:
        auth = api_info.get("SYNO.API.Auth") or {}
        path = str(auth.get("path") or "entry.cgi")
        url = _dsm_url(s.synology_url, path)

        auth_method = _env_str("DSM_AUTH_METHOD", "GET").upper()
        session_name = _env_str("DSM_SESSION_NAME", "DownloadStation")
        auth_version = _env_str("DSM_AUTH_VERSION", "6")

        payload: dict[str, Any] = {
            "api": "SYNO.API.Auth",
            "version": auth_version,
            "method": "logout",
            "session": session_name,
            "_sid": sess.sid,
        }
        if sess.synotoken:
            payload["SynoToken"] = sess.synotoken

        _http_request(
            s,
            method=auth_method,
            url=url,
            params=(payload if auth_method == "GET" else None),
            data=(payload if auth_method != "GET" else None),
            timeout=getattr(s, "dsm_logout_timeout", 6),
            api_name="SYNO.API.Auth.logout",
            session=session,
            allow_non_json=True,  # logout peut renvoyer des trucs bizarres, on s'en fiche
        )
    except Exception:
        pass


# ============================================================
# FileStation - mkdir
# ============================================================

def filestation_mkdir(
    s: Settings,
    api_info: dict[str, Any],
    sess: DsmSession,
    *,
    parent_path: str,
    name: str,
    session: requests.Session | None = None,
) -> None:
    """
    Crée un dossier via SYNO.FileStation.CreateFolder.
    - force_parent=true (DSM crée les parents manquants si possible)
    """
    fs = api_info.get("SYNO.FileStation.CreateFolder") or {}
    path = str(fs.get("path") or "entry.cgi")
    url = _dsm_url(s.synology_url, path)
    version = str(fs.get("maxVersion") or fs.get("minVersion") or 2)

    # DSM attend souvent des listes JSON dans folder_path/name
    params: dict[str, Any] = {
        "api": "SYNO.FileStation.CreateFolder",
        "version": version,
        "method": "create",
        "folder_path": json.dumps([parent_path]),
        "name": json.dumps([name]),
        "force_parent": "true",
        "_sid": sess.sid,
    }
    if sess.synotoken:
        params["SynoToken"] = sess.synotoken

    http_status, js = _http_request(
        s,
        method=_env_str("DSM_FS_METHOD", "GET").upper(),
        url=url,
        params=params,
        timeout=getattr(s, "dsm_task_timeout", 10),
        api_name="SYNO.FileStation.CreateFolder.create",
        session=session,
    )

    if not (js and js.get("success")):
        code = _extract_error_code(js)
        raise SynologyApiError(
            "SYNO.FileStation.CreateFolder.create",
            code,
            http_status,
            "mkdir failed",
            resp=_safe_resp_min(js),
        )


# ============================================================
# DownloadStation - destination formats
# ============================================================

def _destination_candidates(dest: str) -> list[str]:
    """
    Génère une liste de candidats pour le paramètre DownloadStation 'destination'.

    DSM est incohérent selon versions/config:
    - parfois attend "downloads/folder" (relatif)
    - parfois "/downloads/folder" (pseudo-absolu)
    - parfois "/volume1/downloads/folder"
    - parfois juste "folder" (dans un dossier par défaut)

    On tente plusieurs formes, en gardant l'unicité, et on finit par "" (pas de param).
    """
    d = (dest or "").strip()
    if not d:
        return [""]  # pas de destination => DS utilise son défaut

    # normalisations
    abs_like = _norm_abs(d)   # "/downloads/x"
    rel_like = _norm_rel(d)   # "downloads/x"
    folder_only = rel_like.split("/")[-1] if rel_like else ""

    out: list[str] = []
    for c in (rel_like, abs_like, folder_only):
        c = (c or "").strip()
        if c and c not in out:
            out.append(c)

    # Cas: l'appelant a déjà un "/volumeX/..."
    if abs_like.startswith("/volume"):
        if abs_like not in out:
            out.insert(0, abs_like)
        # tentative sans "/volume1"
        # "/volume1/downloads/x" -> "/downloads/x"
        parts = abs_like.split("/", 3)  # ["", "volume1", "downloads", "x..."] ou moins
        if len(parts) >= 3:
            no_vol = "/" + (parts[2] if len(parts) == 3 else parts[2] + "/" + parts[3])
            no_vol = _norm_abs(no_vol)
            if no_vol and no_vol not in out:
                out.append(no_vol)

    if "" not in out:
        out.append("")
    return out


# ============================================================
# DownloadStation - task/create
# ============================================================

def downloadstation_task_create(
    s: Settings,
    api_info: dict[str, Any],
    sess: DsmSession,
    *,
    uri: str,
    destination: str,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """
    Crée une tâche DownloadStation (SYNO.DownloadStation.Task).

    Stratégie:
    - On tente plusieurs formats de "destination" via _destination_candidates().
    - On considère que DSM peut renvoyer HTTP 200 même en erreur → on parse JSON success/error.code.
    - Certains codes (101/105/403) sont souvent liés à destination invalide ou non autorisée :
      dans ce cas, on continue à tester d'autres destinations.
    """
    ds = api_info.get("SYNO.DownloadStation.Task") or {}
    path = str(ds.get("path") or "DownloadStation/task.cgi")
    url = _dsm_url(s.synology_url, path)
    version = str(ds.get("maxVersion") or ds.get("minVersion") or 3)

    method = _env_str("DSM_DS_METHOD", "GET").upper()

    last_err: SynologyApiError | None = None

    for dest in _destination_candidates(destination):
        params: dict[str, Any] = {
            "api": "SYNO.DownloadStation.Task",
            "version": version,
            "method": "create",
            "_sid": sess.sid,
            "uri": uri,  # ATTENTION: l'URL peut être longue; ne pas logger
        }
        if dest:
            params["destination"] = dest
        if sess.synotoken:
            params["SynoToken"] = sess.synotoken

        # On log seulement la destination, jamais l'URI
        logger.info("[DSM][DS] task/create method=%s dest=%r token=%s", method, dest, "yes" if sess.synotoken else "no")

        http_status, js = _http_request(
            s,
            method=method,
            url=url,
            params=(params if method == "GET" else None),
            data=(params if method != "GET" else None),
            timeout=getattr(s, "dsm_task_timeout", 10),
            api_name="SYNO.DownloadStation.Task.create",
            session=session,
        )

        if js and js.get("success"):
            return js

        code = _extract_error_code(js)
        last_err = SynologyApiError(
            api="SYNO.DownloadStation.Task.create",
            code=code,
            http_status=http_status,
            message="DS task/create failed",
            resp=_safe_resp_min(js),
        )

        # 101/105/403 => typiquement destination invalide / pas autorisée
        if code in (101, 105, 403):
            continue

        # Autres erreurs: on stop immédiatement
        raise last_err

    # Tous les formats destination ont échoué
    raise last_err or SynologyApiError(
        api="SYNO.DownloadStation.Task.create",
        code=101,
        http_status=200,
        message="DS task/create failed",
        resp={"success": False, "error": {"code": 101}},
    )