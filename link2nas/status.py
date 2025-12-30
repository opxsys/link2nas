# link2nas/status.py

from __future__ import annotations

import json
import time
import requests

from . import config
from .alldebrid import get_premium_info_cached as _ad_get_premium_info_cached
from .synology import synology_ping_safe

from .config import Settings
import redis


def _join_url(base: str, path: str) -> str:
    base = (base or "").rstrip("/")
    path = (path or "").strip()
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _ad_request(method: str, path: str, data: dict | None, timeout: int) -> tuple[bool, dict]:
    url = _join_url(config.ALLDEBRID_BASE_URL, path)
    headers = {"Authorization": f"Bearer {config.ALLDEBRID_APIKEY}"}
    try:
        r = requests.request(method=method, url=url, headers=headers, data=data, timeout=timeout)
        js = None
        try:
            js = r.json()
        except Exception:
            js = None

        if isinstance(js, dict) and isinstance(js.get("error"), dict) and js["error"].get("code") == "DISCONTINUED":
            return False, {"ok": False, "kind": "discontinued", "code": "DISCONTINUED", "message": "API endpoint discontinued", "http_status": r.status_code, "url": url}

        if isinstance(js, dict):
            return True, {"ok": True, "http_status": r.status_code, "url": url, "status": js.get("status"), "error_code": (js.get("error") or {}).get("code") if isinstance(js.get("error"), dict) else None, "deprecated": bool(js.get("deprecated"))}

        return False, {"ok": False, "kind": "bad_payload", "code": "BAD_PAYLOAD", "message": "Non-JSON response", "http_status": r.status_code, "url": url}
    except requests.exceptions.Timeout:
        return False, {"ok": False, "kind": "timeout", "code": "TIMEOUT", "message": "timeout", "url": url}
    except requests.exceptions.RequestException as e:
        return False, {"ok": False, "kind": "network", "code": "NETWORK_ERROR", "message": str(e), "url": url}
    except Exception as e:
        return False, {"ok": False, "kind": "unknown", "code": "EXCEPTION", "message": str(e), "url": url}


def get_premium_info_cached(s: Settings, rdb: redis.Redis, ttl_seconds: int = 300) -> dict:
    """
    Webapp appelle status.get_premium_info_cached(s, rdb, ttl_seconds).
    On délègue à alldebrid.get_premium_info_cached(s, rdb, ttl_seconds).
    """
    return _ad_get_premium_info_cached(s, rdb, ttl_seconds=ttl_seconds)

def premium_color_from_days(days_left: int | None) -> tuple[str, str]:
    if days_left is None:
        return "gray", "inconnu"
    if days_left >= config.PREMIUM_GREEN_DAYS:
        return "green", f"{days_left}j"
    if config.PREMIUM_YELLOW_DAYS <= days_left < config.PREMIUM_GREEN_DAYS:
        return "yellow", f"{days_left}j"
    return "red", f"{days_left}j"


def build_status_context(s: Settings, rdb: redis.Redis):
    ad_ping_ok, ad_ping = _ad_request("GET", config.AD_PING_PATH, data=None, timeout=config.STATUS_HTTP_TIMEOUT)

    endpoint_tests = [
        ("user", "GET", config.AD_ENDPOINTS["user"], None),
        ("magnet_status", "POST", config.AD_ENDPOINTS["magnet_status"], {"id[]": [0]}),
        ("magnet_files", "POST", config.AD_ENDPOINTS["magnet_files"], {"id[]": [0]}),
        ("link_unlock", "POST", config.AD_ENDPOINTS["link_unlock"], {"link": "http://example.invalid"}),
    ]

    ad_endpoints = []
    endpoints_discontinued = False
    endpoints_timeout_or_network = False

    for name, method, path, payload in endpoint_tests:
        ok, info = _ad_request(method, path, data=payload, timeout=config.STATUS_HTTP_TIMEOUT)
        state = "ok"
        color = "green"
        if not ok:
            code = info.get("code")
            if code == "DISCONTINUED":
                state = "discontinued"
                color = "red"
                endpoints_discontinued = True
            else:
                state = info.get("kind") or "error"
                color = "yellow"
                endpoints_timeout_or_network = True
        if ok and info.get("deprecated"):
            state = "deprecated"
            color = "yellow"
        ad_endpoints.append({
            "name": name,
            "method": method,
            "path": path,
            "color": color,
            "state": state,
            "http_status": info.get("http_status"),
            "error_code": info.get("error_code"),
        })

    premium = get_premium_info_cached(s, rdb, ttl_seconds=300)

    days_left = None
    if premium.get("premium_until_ts"):
        try:
            days_left = int((int(premium["premium_until_ts"]) - int(time.time())) / 86400)
        except Exception:
            days_left = None

    premium_color, premium_label = premium_color_from_days(days_left)
    premium_ok = bool(premium.get("ok"))

    # Redis check (utilise le client injecté)
    redis_info = {"ok": False, "message": "unknown"}
    try:
        pong = rdb.ping()
        redis_info = {"ok": bool(pong), "message": "OK" if pong else "PING failed"}
    except Exception as e:
        redis_info = {"ok": False, "message": str(e)}

    nas_info = ping_safe(timeout=config.STATUS_DSM_TIMEOUT)

    overall = "green"
    if endpoints_discontinued:
        overall = "red"
    elif (not ad_ping_ok) or endpoints_timeout_or_network or (not redis_info["ok"]) or (nas_info.get("enabled") and not nas_info.get("ok")) or (not premium_ok):
        overall = "yellow"

    return {
        "overall": overall,
        "ad_ping_ok": ad_ping_ok,
        "ad_ping": ad_ping,
        "ad_endpoints": ad_endpoints,
        "premium": premium,
        "premium_days_left": days_left,
        "premium_color": premium_color,
        "premium_label": premium_label,
        "redis_info": redis_info,
        "nas_info": nas_info,
        "NAS_ENABLED": config.NAS_ENABLED,
    }
