# link2nas/status_checks.py
from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import redis
import requests

from .config import Settings
from .status import get_premium_info_cached
from .synology import synology_ping_safe


# ============================================================
# AllDebrid HTTP checks
# ============================================================

def _join_url(base: str, path: str) -> str:
    base = (base or "").rstrip("/")
    path = (path or "").strip()
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _endpoint_is_discontinued(js: dict | None) -> bool:
    if not isinstance(js, dict):
        return False
    err = js.get("error")
    if not isinstance(err, dict):
        return False
    return err.get("code") == "DISCONTINUED"


def ad_request_check(
    s: Settings,
    method: str,
    path: str,
    *,
    data: dict | None = None,
    timeout: int = 6,
) -> tuple[bool, dict]:
    """
    Low-impact AllDebrid probe for status pages.
    Returns (ok, info) with a stable shape.
    """
    url = _join_url(s.alldebrid_base_url, path)
    headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}

    try:
        r = requests.request(method=method, url=url, headers=headers, data=data, timeout=timeout)

        js = None
        try:
            js = r.json()
        except Exception:
            js = None

        if _endpoint_is_discontinued(js):
            return False, {
                "ok": False,
                "kind": "discontinued",
                "code": "DISCONTINUED",
                "message": "API endpoint discontinued",
                "http_status": r.status_code,
                "url": url,
            }

        if isinstance(js, dict):
            return True, {
                "ok": True,
                "http_status": r.status_code,
                "url": url,
                "status": js.get("status"),
                "error_code": (js.get("error") or {}).get("code") if isinstance(js.get("error"), dict) else None,
                "deprecated": bool(js.get("deprecated")) if isinstance(js, dict) else False,
            }

        return False, {
            "ok": False,
            "kind": "bad_payload",
            "code": "BAD_PAYLOAD",
            "message": "Non-JSON or invalid JSON response",
            "http_status": r.status_code,
            "url": url,
        }

    except requests.exceptions.Timeout:
        return False, {"ok": False, "kind": "timeout", "code": "TIMEOUT", "message": "timeout", "url": url}
    except requests.exceptions.RequestException as e:
        return False, {"ok": False, "kind": "network", "code": "NETWORK_ERROR", "message": str(e), "url": url}
    except Exception as e:
        return False, {"ok": False, "kind": "unknown", "code": "EXCEPTION", "message": str(e), "url": url}


# ============================================================
# Premium rendering helper
# ============================================================

def premium_color_from_days(s: Settings, days_left: int | None) -> tuple[str, str]:
    green_days = int(getattr(s, "premium_green_days", 14) or 14)
    yellow_days = int(getattr(s, "premium_yellow_days", 7) or 7)

    if days_left is None:
        return "gray", "inconnu"
    if days_left >= green_days:
        return "green", f"{days_left}j"
    if yellow_days <= days_left < green_days:
        return "yellow", f"{days_left}j"
    return "red", f"{days_left}j"


# ============================================================
# Full status build (template + API)
# ============================================================

def build_status_snapshot(s: Settings, rdb: redis.Redis) -> dict[str, Any]:
    """
    Compute status snapshot shared by:
    - /status (template)
    - /api/status (json)
    """
    http_timeout = int(getattr(s, "status_http_timeout", 6) or 6)
    dsm_timeout = int(getattr(s, "status_dsm_timeout", 6) or 6)
    ad_ping_path = str(getattr(s, "ad_ping_path", "/v4/ping") or "/v4/ping")

    ad_ping_ok, ad_ping = ad_request_check(s, "GET", ad_ping_path, data=None, timeout=http_timeout)

    endpoint_tests = [
        ("user", "GET", s.ad_endpoints["user"], None),
        ("magnet_status", "POST", s.ad_endpoints["magnet_status"], {"id[]": [0]}),
        ("magnet_files", "POST", s.ad_endpoints["magnet_files"], {"id[]": [0]}),
        ("link_unlock", "POST", s.ad_endpoints["link_unlock"], {"link": "http://example.invalid"}),
    ]

    ad_endpoints: list[dict[str, Any]] = []
    endpoints_discontinued = False
    endpoints_timeout_or_network = False

    for name, method, path, payload in endpoint_tests:
        ok, info = ad_request_check(s, method, path, data=payload, timeout=http_timeout)
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

        ad_endpoints.append(
            {
                "name": name,
                "method": method,
                "path": path,
                "color": color,
                "state": state,
                "http_status": info.get("http_status"),
                "error_code": info.get("error_code"),
            }
        )

    premium = get_premium_info_cached(s, rdb, ttl_seconds=300)
    days_left = None
    premium_until_ts = premium.get("premium_until_ts")
    if premium_until_ts:
        try:
            now_ts = int(time.time())
            days_left = max(-9999, int((int(premium_until_ts) - now_ts) / 86400))
        except Exception:
            days_left = None

    premium_color, premium_label = premium_color_from_days(s, days_left)
    premium_ok = bool(premium.get("ok"))

    redis_info = {"ok": False, "message": "unknown"}
    try:
        pong = rdb.ping()
        redis_info = {"ok": bool(pong), "message": "OK" if pong else "PING failed"}
    except Exception as e:
        redis_info = {"ok": False, "message": str(e)}

    nas_info = synology_ping_safe(s, timeout=dsm_timeout)

    overall = "green"
    if endpoints_discontinued:
        overall = "red"
    elif (not ad_ping_ok) or endpoints_timeout_or_network or (not redis_info["ok"]) or (nas_info.get("enabled") and not nas_info.get("ok")) or (not premium_ok):
        overall = "yellow"

    return {
        "now": datetime.now(),
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
        "nas_enabled": bool(s.nas_enabled),
    }
