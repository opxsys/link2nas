from __future__ import annotations

import json
from typing import Any

import requests
import redis

from .config import Settings


def normalize_alldebrid_error(err: dict) -> dict:
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


def get_user_safe(s: Settings) -> tuple[bool, dict]:
    url = f"{s.alldebrid_base_url}{s.ad_endpoints['user']}"
    headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}

    try:
        r = requests.get(url, headers=headers, timeout=s.alldebrid_timeout)
        js = r.json() if r.content else None

        if not r.ok:
            if isinstance(js, dict):
                return False, normalize_alldebrid_error((js.get("error") or {}))
            return False, {"kind": "http_error", "code": f"HTTP_{r.status_code}", "message": "user http error"}

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


def upload_magnet_safe(s: Settings, magnet_link: str) -> tuple[bool, dict]:
    url = f"{s.alldebrid_base_url}{s.ad_endpoints['magnet_upload']}"
    headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}
    data = {"magnets[]": magnet_link}

    try:
        r = requests.post(url, headers=headers, data=data, timeout=s.alldebrid_timeout)
        js = r.json() if r.content else None

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


def unlock_link_safe(s: Settings, link: str) -> tuple[bool, dict]:
    url = f"{s.alldebrid_base_url}{s.ad_endpoints['link_unlock']}"
    headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}
    data = {"link": link}

    try:
        r = requests.post(url, headers=headers, data=data, timeout=s.alldebrid_timeout)
        js = r.json() if r.content else None

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

def get_magnet_files_safe(s, magnet_id: str):
    try:
        url = f"{s.alldebrid_base_url}{s.ad_endpoints['magnet_files']}"
        headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}
        r = requests.post(url, headers=headers, data={"id[]": str(magnet_id)}, timeout=s.alldebrid_timeout)
        js = r.json()
        if not r.ok or js.get("status") != "success":
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
    """
    Retourne un dict "plat" avec au moins:
      {status, progress, size, downloaded}
    en essayant d'être compatible v4 / v4.1.
    """
    url = f"{s.alldebrid_base_url}{s.ad_endpoints['magnet_status']}"
    headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}

    try:
        r = requests.post(url, headers=headers, data={"id[]": str(magnet_id)}, timeout=s.alldebrid_timeout)
        js = r.json() if r.content else None

        if (not r.ok) or (not isinstance(js, dict)) or js.get("status") != "success":
            err = (js or {}).get("error") if isinstance(js, dict) else None
            return False, {
                "code": (err or {}).get("code") if isinstance(err, dict) else f"HTTP_{r.status_code}",
                "message": (err or {}).get("message") if isinstance(err, dict) else "magnet/status failed",
            }

        data = js.get("data") or {}
        magnets = data.get("magnets") or []
        if not magnets:
            # Parfois l'API renvoie autre chose selon version; fallback brut
            return True, {"raw": data}

        m = magnets[0] or {}

        # champs typiques (selon version API)
        st = (m.get("status") or m.get("state") or "").strip().lower()
        progress = m.get("progress")
        size = m.get("size")
        downloaded = m.get("downloaded")

        # certains payloads utilisent d'autres noms
        if progress is None:
            progress = m.get("downloadPercent") or m.get("download_percent")

        out = {
            "status": st or None,
            "progress": progress,
            "size": size,
            "downloaded": downloaded,
        }
        return True, out

    except requests.exceptions.Timeout:
        return False, {"code": "TIMEOUT", "message": "magnet/status timeout"}
    except requests.exceptions.RequestException as e:
        return False, {"code": "NETWORK_ERROR", "message": str(e)}
    except Exception as e:
        return False, {"code": "EXCEPTION", "message": str(e)}

