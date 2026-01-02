# link2nas/alldebrid.py
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlparse

import redis
import requests

from .config import Settings

logger = logging.getLogger("link2nas.alldebrid")

# ==================================================
# Errors: normalisation AllDebrid -> format interne
# ==================================================
def normalize_alldebrid_error(err: dict) -> dict:
    """
    Normalise une erreur AllDebrid au format interne:
      {"kind": "...", "code": "...", "message": "..."}
    """
    err = err or {}
    code = str(err.get("code") or "UNLOCK_ERROR")
    msg = str(err.get("message") or "unlock failed")

    kind = "unknown"
    if code in {"LINK_HOST_NOT_SUPPORTED"}:
        kind = "host_not_supported"
    elif code in {"LINK_DOWN", "LINK_DEAD", "LINK_ERROR"}:
        kind = "link_down"
    elif code in {"HOST_UNAVAILABLE", "LINK_HOST_UNAVAILABLE"}:
        kind = "host_unavailable"
    elif code in {"AUTH_BAD_APIKEY", "AUTH_MISSING_APIKEY"}:
        kind = "alldebrid_auth"
    elif code in {"MUST_BE_PREMIUM"}:
        kind = "premium_required"
    elif code in {"LINK_PASSWORD_REQUIRED"}:
        kind = "password_required"
    elif code in {"LINK_TOO_MANY_CONNECTIONS"}:
        kind = "rate_limited"

    return {"kind": kind, "code": code, "message": msg}


# ==================================================
# HTTP: wrapper requêtes AllDebrid + JSON helpers
# ==================================================
def _ad_headers(s: Settings) -> dict[str, str]:
    return {"Authorization": f"Bearer {s.alldebrid_apikey}"}


def _ad_request(
    s: Settings,
    method: str,
    path: str,
    *,
    params: dict | None = None,
    data: dict | None = None,
    timeout: int | None = None,
) -> requests.Response:
    """
    Wrapper HTTP AllDebrid:
    - concat base_url + path
    - injecte Authorization
    - gère timeout
    - suit les redirects selon la config (ou force un follow 1 fois si 30x inattendu)
    """
    url = f"{s.alldebrid_base_url}{path}"
    allow = bool(getattr(s, "alldebrid_follow_redirects", True))
    tout = int(timeout or s.alldebrid_timeout)

    r = requests.request(
        method=method.upper(),
        url=url,
        headers=_ad_headers(s),
        params=params,
        data=data,
        timeout=tout,
        allow_redirects=allow,
    )

    # Si allow_redirects=False mais l’API renvoie un 30x, on suit 1 fois (defensif).
    if (not allow) and r.status_code in (301, 302, 307, 308):
        loc = r.headers.get("Location")
        if loc:
            r = requests.request(
                method=method.upper(),
                url=loc,
                headers=_ad_headers(s),
                params=params,
                data=data,
                timeout=tout,
                allow_redirects=True,
            )

    return r


def _json_or_none(r: requests.Response) -> Any:
    try:
        return r.json() if r.content else None
    except Exception:
        return None


# ==================================================
# URL helpers + policy redirector
# ==================================================
def _redact_url(u: str) -> dict:
    """
    Pour logs: évite d’imprimer l’URL en clair.
    Retourne {"host": "...", "hash": "..."}.
    """
    s = str(u or "").strip()
    host = ""
    try:
        host = (urlparse(s).netloc or "").lower().replace("www.", "")
    except Exception:
        host = ""
    h = hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:10] if s else ""
    return {"host": host, "hash": h}


def _host_path(url: str) -> tuple[str, str]:
    try:
        p = urlparse(url)
        host = (p.netloc or "").lower().replace("www.", "")
        path = p.path or ""
        return host, path
    except Exception:
        return "", ""


def _redirector_expand_should_run(url: str) -> bool:
    """
    Décide si on appelle /link/redirector (expand).
    - rapidgator.net: bypass expand (fallback unlock)
    - 1fichier.com: expand UNIQUEMENT pour /dir/ (sinon bypass unlock)
    """
    host, path = _host_path(url)
    if host in {"rapidgator.net"}:
        return False
    if host == "1fichier.com":
        return path.startswith("/dir/")
    return True


# ==================================================
# AllDebrid: User / Premium
# ==================================================
def get_user_safe(s: Settings) -> tuple[bool, dict]:
    try:
        r = _ad_request(s, "GET", s.ad_endpoints["user"], timeout=s.alldebrid_timeout)
        js = _json_or_none(r)

        if not r.ok:
            if isinstance(js, dict):
                return False, normalize_alldebrid_error((js.get("error") or {}))
            return False, {
                "kind": "http_error",
                "code": f"HTTP_{r.status_code}",
                "message": "user http error",
            }

        if not isinstance(js, dict) or js.get("status") != "success":
            err = (js or {}).get("error") or {"code": "USER_ERROR", "message": "user endpoint failed"}
            return False, normalize_alldebrid_error(err)

        user = ((js.get("data") or {}).get("user") or {})
        if not isinstance(user, dict):
            return False, {"kind": "unknown", "code": "USER_BAD_PAYLOAD", "message": "bad user payload"}

        return True, user

    except requests.exceptions.Timeout:
        return False, {"kind": "timeout", "code": "TIMEOUT", "message": "AllDebrid user timeout"}
    except requests.exceptions.RequestException as e:
        return False, {"kind": "network", "code": "NETWORK_ERROR", "message": str(e)}
    except Exception as e:
        return False, {"kind": "unknown", "code": "EXCEPTION", "message": str(e)}


def get_premium_info_cached(s: Settings, rdb: redis.Redis, ttl_seconds: int = 300) -> dict:
    cache_key = "alldebrid:user:cache:v1"
    try:
        raw = rdb.get(cache_key)
        if raw:
            return json.loads(raw.decode("utf-8"))
    except Exception:
        pass

    ok, user_or_err = get_user_safe(s)
    if not ok:
        info = {"ok": False, "error": user_or_err, "is_premium": None, "premium_until_ts": None}
    else:
        u = user_or_err
        premium_until = u.get("premiumUntil")
        try:
            premium_until_ts = int(str(premium_until).strip()) if premium_until is not None else None
        except Exception:
            premium_until_ts = None

        info = {
            "ok": True,
            "username": u.get("username"),
            "is_premium": bool(u.get("isPremium")),
            "is_trial": bool(u.get("isTrial")),
            "is_subscribed": bool(u.get("isSubscribed")),
            "premium_until_ts": premium_until_ts,
        }

    try:
        rdb.setex(cache_key, ttl_seconds, json.dumps(info))
    except Exception:
        pass

    return info


# ==================================================
# AllDebrid: Magnet
# ==================================================
def upload_magnet_safe(s: Settings, magnet_link: str) -> tuple[bool, dict]:
    data = {"magnets[]": magnet_link}

    try:
        r = _ad_request(s, "POST", s.ad_endpoints["magnet_upload"], data=data, timeout=s.alldebrid_timeout)
        js = _json_or_none(r)

        if not r.ok:
            if isinstance(js, dict):
                return False, normalize_alldebrid_error((js.get("error") or {}))
            return False, {"kind": "http_error", "code": f"HTTP_{r.status_code}", "message": "upload http error"}

        if not isinstance(js, dict) or js.get("status") != "success":
            err = (js or {}).get("error") or {"code": "MAGNET_UPLOAD_FAILED", "message": "upload failed"}
            return False, normalize_alldebrid_error(err)

        magnets = (js.get("data") or {}).get("magnets") or []
        if not magnets:
            return False, {"kind": "unknown", "code": "MAGNET_EMPTY", "message": "No magnet returned"}

        m = magnets[0] or {}
        if "id" not in m:
            err = m.get("error") or {}
            if err:
                return False, normalize_alldebrid_error(err)
            return False, {"kind": "unknown", "code": "MAGNET_UPLOAD_FAILED", "message": "missing id"}

        return True, {"id": int(m.get("id")), "name": str(m.get("name") or "").strip() or "magnet"}

    except requests.exceptions.Timeout:
        return False, {"kind": "timeout", "code": "TIMEOUT", "message": "upload timeout"}
    except requests.exceptions.RequestException as e:
        return False, {"kind": "network", "code": "NETWORK_ERROR", "message": str(e)}
    except Exception as e:
        return False, {"kind": "unknown", "code": "EXCEPTION", "message": str(e)}


def get_magnet_files_safe(s: Settings, magnet_id: str) -> tuple[bool, list | dict]:
    try:
        r = _ad_request(
            s,
            "POST",
            s.ad_endpoints["magnet_files"],
            data={"id[]": str(magnet_id)},
            timeout=s.alldebrid_timeout,
        )
        js = _json_or_none(r)

        if (not r.ok) or (not isinstance(js, dict)) or js.get("status") != "success":
            err = js.get("error") if isinstance(js, dict) else None
            return False, {
                "code": (err or {}).get("code") if isinstance(err, dict) else f"HTTP_{r.status_code}",
                "message": (err or {}).get("message") if isinstance(err, dict) else "request failed",
            }

        magnets = ((js.get("data") or {}).get("magnets") or [])
        if not magnets:
            return True, []

        files = (magnets[0] or {}).get("files") or []
        return True, files

    except Exception as e:
        return False, {"code": "EXCEPTION", "message": str(e)}


def get_magnet_status_safe(s: Settings, magnet_id: str) -> tuple[bool, dict]:
    try:
        r = _ad_request(
            s,
            "POST",
            s.ad_endpoints["magnet_status"],
            data={"id[]": str(magnet_id)},
            timeout=s.alldebrid_timeout,
        )
        js = _json_or_none(r)

        if (not r.ok) or (not isinstance(js, dict)) or js.get("status") != "success":
            err = (js or {}).get("error") if isinstance(js, dict) else None
            return False, {
                "code": (err or {}).get("code") if isinstance(err, dict) else f"HTTP_{r.status_code}",
                "message": (err or {}).get("message") if isinstance(err, dict) else "magnet/status failed",
            }

        data = js.get("data") or {}
        magnets = data.get("magnets") or []
        if not magnets:
            return True, {"raw": data}

        m = magnets[0] or {}
        st = (m.get("status") or m.get("state") or "").strip().lower()
        progress = m.get("progress")
        size = m.get("size")
        downloaded = m.get("downloaded")

        if progress is None:
            progress = m.get("downloadPercent") or m.get("download_percent")

        return True, {"status": st or None, "progress": progress, "size": size, "downloaded": downloaded}

    except requests.exceptions.Timeout:
        return False, {"code": "TIMEOUT", "message": "magnet/status timeout"}
    except requests.exceptions.RequestException as e:
        return False, {"code": "NETWORK_ERROR", "message": str(e)}
    except Exception as e:
        return False, {"code": "EXCEPTION", "message": str(e)}


# ==================================================
# AllDebrid: Link unlock (direct)
# ==================================================
def unlock_link_safe(s: Settings, link: str) -> tuple[bool, dict]:
    data = {"link": link}

    try:
        r = _ad_request(s, "POST", s.ad_endpoints["link_unlock"], data=data, timeout=s.alldebrid_timeout)
        js = _json_or_none(r)

        if not r.ok:
            if isinstance(js, dict):
                return False, normalize_alldebrid_error((js.get("error") or {}))
            return False, {"kind": "http_error", "code": f"HTTP_{r.status_code}", "message": "unlock http error"}

        if not isinstance(js, dict) or js.get("status") != "success":
            err = (js or {}).get("error") or {"code": "UNLOCK_ERROR", "message": "unlock failed"}
            return False, normalize_alldebrid_error(err)

        data_out = (js.get("data") or {})
        if not isinstance(data_out, dict):
            return False, {"kind": "unknown", "code": "UNLOCK_BAD_PAYLOAD", "message": "bad unlock payload"}

        return True, data_out

    except requests.exceptions.Timeout:
        return False, {"kind": "timeout", "code": "TIMEOUT", "message": "unlock timeout"}
    except requests.exceptions.RequestException as e:
        return False, {"kind": "network", "code": "NETWORK_ERROR", "message": str(e)}
    except Exception as e:
        return False, {"kind": "unknown", "code": "EXCEPTION", "message": str(e)}


# ==================================================
# AllDebrid: Redirectors (cache + matching)
# ==================================================
_REDIRECTORS_CACHE_KEY = "alldebrid:redirectors:cache:v1"


def _compile_redirectors(payload: dict) -> list[dict]:
    data = (payload or {}).get("data") or {}
    redirectors = data.get("redirectors") or {}
    if not isinstance(redirectors, dict):
        return []

    out: list[dict] = []
    for name, info in redirectors.items():
        if not isinstance(info, dict):
            continue

        domains = info.get("domains") or []
        regexps = info.get("regexps") or []
        regexp = info.get("regexp") or ""

        domains = [str(d).strip().lower() for d in domains if str(d).strip()]
        regexps = [str(x).strip() for x in regexps if str(x).strip()]
        regexp = str(regexp).strip()

        out.append(
            {
                "name": str(info.get("name") or name),
                "type": str(info.get("type") or ""),
                "domains": domains,
                "regexps": regexps,
                "regexp": regexp,
            }
        )
    return out


def get_redirectors_cached(s: Settings, rdb: redis.Redis) -> list[dict]:
    ttl = int(getattr(s, "alldebrid_redirector_cache_ttl", 86400) or 86400)

    try:
        raw = rdb.get(_REDIRECTORS_CACHE_KEY)
        if raw:
            val = json.loads(raw.decode("utf-8"))
            if isinstance(val, list):
                return val
    except Exception:
        pass

    try:
        r = _ad_request(s, "GET", s.ad_endpoints["hosts"], timeout=s.alldebrid_timeout)
        js = _json_or_none(r)
        if (not r.ok) or (not isinstance(js, dict)) or js.get("status") != "success":
            return []

        redirectors = _compile_redirectors(js)
        try:
            rdb.setex(_REDIRECTORS_CACHE_KEY, ttl, json.dumps(redirectors))
        except Exception:
            pass
        return redirectors

    except Exception:
        return []


def is_redirector_url(s: Settings, rdb: redis.Redis, url: str) -> tuple[bool, str | None]:
    """
    Détermine si l’URL correspond à un redirector connu AllDebrid.

    Contrôles via env (sans passer par Settings):
      - AD_REDIRECTOR_EXCLUDE_REGEXPS         (séparateurs ; ou ,)
      - AD_REDIRECTOR_EXCLUDE_BY_NETLOC_JSON  (json: {"example.com": ["rx1","rx2"]})
    """
    u = str(url or "").strip()
    if not u:
        return False, None

    low = u.lower()
    netloc = (urlparse(u).netloc or "").lower().replace("www.", "")

    def _split_env_regexps(val: str) -> list[str]:
        if not val:
            return []
        return [p.strip() for p in re.split(r"[;,]", val) if p.strip()]

    exclude_regexps = _split_env_regexps(str(os.getenv("AD_REDIRECTOR_EXCLUDE_REGEXPS", "") or "").strip())

    exclude_by_netloc: dict[str, list[str]] = {}
    raw_json = str(os.getenv("AD_REDIRECTOR_EXCLUDE_BY_NETLOC_JSON", "") or "").strip()
    if raw_json:
        try:
            tmp = json.loads(raw_json)
            if isinstance(tmp, dict):
                for k, v in tmp.items():
                    k2 = (str(k or "").strip().lower() or "").replace("www.", "")
                    if not k2:
                        continue
                    if isinstance(v, list):
                        exclude_by_netloc[k2] = [str(x).strip() for x in v if str(x).strip()]
        except Exception as e:
            logger.warning("[REDIR] bad AD_REDIRECTOR_EXCLUDE_BY_NETLOC_JSON: %s", str(e))

    for rx in exclude_regexps:
        try:
            if re.search(rx, u, flags=re.IGNORECASE):
                rd = _redact_url(u)
                logger.info("[REDIR] skip_by_exclude_rx host=%r url_hash=%s rx=%r", rd["host"], rd["hash"], rx)
                return False, None
        except re.error as e:
            logger.warning("[REDIR] bad exclude regexp rx=%r err=%s", rx, str(e))

    for rx in (exclude_by_netloc.get(netloc) or []):
        try:
            if re.search(rx, u, flags=re.IGNORECASE):
                logger.info("[REDIR] skip_by_netloc_exclude netloc=%r rx=%r", netloc, rx)
                return False, None
        except re.error as e:
            logger.warning("[REDIR] bad netloc exclude regexp netloc=%r rx=%r err=%s", netloc, rx, str(e))

    redirs = get_redirectors_cached(s, rdb) or []
    rd = _redact_url(u)
    logger.debug("[REDIR] check host=%r url_hash=%s redirs=%d", rd["host"], rd["hash"], len(redirs))

    for info in redirs:
        name = str(info.get("name") or "").strip() or "?"
        domains = info.get("domains") or []
        regexps = info.get("regexps") or []

        domain_hit = False
        for d in domains:
            d = (str(d) or "").strip().lower()
            if d and d in low:
                domain_hit = True
                break
        if not domain_hit:
            continue

        if isinstance(regexps, list) and len(regexps) > 0:
            for rx in regexps:
                rx_s = (str(rx) or "").strip()
                if not rx_s:
                    continue
                try:
                    if re.search(rx_s, u):
                        rd2 = _redact_url(u)
                        logger.info("[REDIR] match_regexp name=%r host=%r url_hash=%s", name, rd2["host"], rd2["hash"])
                        return True, name
                except re.error:
                    continue

            logger.debug("[REDIR] domain_hit_no_regexp name=%r host=%r url_hash=%s", name, rd["host"], rd["hash"])
            continue

        logger.info("[REDIR] match_domain_only name=%r host=%r url_hash=%s", name, rd["host"], rd["hash"])
        return True, name

    return False, None


# ==================================================
# AllDebrid: Redirector expand
# ==================================================
def redirector_expand_safe(s: Settings, link: str) -> tuple[bool, dict]:
    """
    POST /link/redirector => { data: { links: [...] } }
    """
    try:
        ep = s.ad_endpoints.get("link_redirector")
        if not ep:
            return False, {"kind": "config", "code": "MISSING_ENDPOINT", "message": "link_redirector endpoint missing"}

        dom = (urlparse(str(link)).netloc or "").lower().replace("www.", "")
        logger.info("[REDIR] expand_request domain=%r", dom)

        r = _ad_request(s, "POST", ep, data={"link": str(link)}, timeout=s.alldebrid_timeout)
        js = _json_or_none(r)

        if (not r.ok) or (not isinstance(js, dict)):
            return False, {"kind": "http_error", "code": f"HTTP_{r.status_code}", "message": "redirector http error"}

        st = (js.get("status") or "").strip().lower()
        if st != "success":
            err = (js.get("error") or {}) if isinstance(js, dict) else {}
            return False, normalize_alldebrid_error(err)

        data = js.get("data") or {}
        links = data.get("links") or []
        if not isinstance(links, list):
            links = []

        links = [str(x).strip() for x in links if str(x).strip()]
        logger.info("[REDIR] expand_success domain=%r links=%d", dom, len(links))
        return True, {"links": links}

    except requests.exceptions.Timeout:
        return False, {"kind": "timeout", "code": "TIMEOUT", "message": "redirector timeout"}
    except requests.exceptions.RequestException as e:
        return False, {"kind": "network", "code": "NETWORK_ERROR", "message": str(e)}
    except Exception as e:
        logger.error("[REDIR] expand_exception=%s", str(e), exc_info=True)
        return False, {"kind": "unknown", "code": "EXCEPTION", "message": str(e)}


# ==================================================
# Public: orchestrateur liens (single entry point)
# ==================================================
def generate_links_safe(s: Settings, rdb: redis.Redis, input_link: str) -> tuple[bool, dict]:
    """
    Point d’entrée unique URL http(s) -> 1 ou N liens directs.

    Retour:
      {
        "links": [
          {"link": "...", "filename": "...", "filesize": ..., "source": "...", "redirector": "...?"}
        ],
        "links_count": N,
        "kind": "single|redirector",
        "redirector": "name?" (optionnel)
      }
    """
    u = (input_link or "").strip()
    if not u:
        return False, {"code": "EMPTY_INPUT", "message": "empty input"}

    is_redir, redir_name = is_redirector_url(s, rdb, u)

    # Redirector détecté mais policy => pas d'expand: fallback unlock "single"
    if is_redir and not _redirector_expand_should_run(u):
        logger.info("[REDIR] bypass_expand_fallback_unlock host=%r", _host_path(u)[0])
        ok, unlocked = unlock_link_safe(s, u)
        if not ok:
            return False, unlocked

        direct = (unlocked.get("link") or "").strip()
        if not direct:
            return False, {"code": "UNLOCK_EMPTY", "message": "unlock returned empty link"}

        return True, {
            "links": [
                {
                    "link": direct,
                    "filename": (unlocked.get("filename") or "").strip(),
                    "filesize": unlocked.get("filesize"),
                    "source": u,
                    "redirector": redir_name,
                }
            ],
            "links_count": 1,
            "kind": "single",
        }

    # Redirector: expand puis (optionnellement) unlock des liens expandés
    if is_redir:
        ok, ex = redirector_expand_safe(s, u)
        if not ok:
            return False, ex

        raw_links = ex.get("links") or []
        must_unlock = str(getattr(s, "ad_redirector_links_must_unlock", "1")).strip().lower() not in {"0", "false", "no"}

        out: list[dict] = []
        for l in raw_links:
            if must_unlock:
                ok2, unlocked = unlock_link_safe(s, l)
                if not ok2:
                    continue
                out.append(
                    {
                        "link": (unlocked.get("link") or "").strip(),
                        "filename": (unlocked.get("filename") or "").strip(),
                        "filesize": unlocked.get("filesize"),
                        "source": l,
                        "redirector": redir_name,
                    }
                )
                sleep_ms = int(str(getattr(s, "ad_unlock_sleep_ms", "0")).strip() or "0")
                if sleep_ms > 0:
                    time.sleep(sleep_ms / 1000.0)
            else:
                out.append({"link": l, "filename": "", "filesize": None, "source": l, "redirector": redir_name})

        out = [x for x in out if (x.get("link") or "").strip()]
        return True, {"links": out, "links_count": len(out), "kind": "redirector", "redirector": redir_name}

    # Non-redirector: unlock direct
    ok, unlocked = unlock_link_safe(s, u)
    if not ok:
        return False, unlocked

    direct = (unlocked.get("link") or "").strip()
    if not direct:
        return False, {"code": "UNLOCK_EMPTY", "message": "unlock returned empty link"}

    return True, {
        "links": [
            {
                "link": direct,
                "filename": (unlocked.get("filename") or "").strip(),
                "filesize": unlocked.get("filesize"),
                "source": u,
            }
        ],
        "links_count": 1,
        "kind": "single",
    }
