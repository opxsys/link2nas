# link2nas/web_helpers.py
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any
from urllib.parse import urlparse


# ============================================================
# Small env helpers (web-only)
# ============================================================

def env_bool(name: str, default: bool = False) -> bool:
    """
    Web-only boolean env parsing.
    Used for request logging toggles (ex: WEB_LOG_BODY).
    """
    v = str(os.getenv(name, "")).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


# ============================================================
# Redaction & log scrubbing
# ============================================================

def redact_url(u: str) -> str:
    """
    Redact a URL/magnet into a stable identifier for logs:
      "<host>#<sha10>"

    Goal:
    - keep enough info for troubleshooting (domain)
    - never log secrets or full URLs
    """
    u = (u or "").strip()
    if not u:
        return ""
    try:
        p = urlparse(u)
        host = (p.netloc or "").lower().replace("www.", "")
        if not host:
            host = "magnet" if u.lower().startswith("magnet:?") else "text"
    except Exception:
        host = "text"
    h = hashlib.sha256(u.encode("utf-8", "ignore")).hexdigest()[:10]
    return f"{host}#{h}"


def sanitize_body(body: str) -> str:
    """
    Sanitize request bodies for logs:
    - size cap
    - redact Bearer tokens & common secret keys
    - redact magnets query
    - rewrite URLs to keep scheme+host+path only
    """
    body = (body or "").strip()
    if not body:
        return ""
    if len(body) > 800:
        body = body[:800] + "…(truncated)"

    # Bearer tokens
    body = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", r"\1***", body)

    # JSON-like secrets
    body = re.sub(
        r'(?i)("?(?:api[_-]?key|token|access[_-]?token|refresh[_-]?token|password|passwd|sid)"?\s*:\s*)"([^"]*)"',
        r'\1"***"',
        body,
    )
    # query-like secrets
    body = re.sub(
        r"(?i)((?:api[_-]?key|token|access[_-]?token|refresh[_-]?token|password|passwd|sid)\s*=\s*)([^&\s]+)",
        r"\1***",
        body,
    )

    # magnet
    body = re.sub(r"(?i)magnet:\?[^ \r\n\t\"']+", "magnet:?***", body)

    def _keep_host_path(m: re.Match[str]) -> str:
        raw = m.group(0)
        try:
            u = urlparse(raw)
            return f"{u.scheme}://{u.netloc}{u.path}"
        except Exception:
            return "https://***"

    body = re.sub(r"(?i)\bhttps?://[^\s\"']+", _keep_host_path, body)
    return body.replace("\r", "\\r").replace("\n", "\\n")


_SENSITIVE_KEYS = {
    "link",
    "url",
    "magnet",
    "download",
    "download_url",
    "streaming",
    "signed",
    "redirector",
    "token",
    "access_token",
    "refresh_token",
    "apikey",
    "api_key",
    "password",
    "passwd",
    "sid",
}


def scrub_for_log(x: Any) -> Any:
    """
    Best-effort scrub of arbitrary structures before logging.
    """
    if x is None:
        return None
    if isinstance(x, (bytes, bytearray)):
        x = x.decode("utf-8", "ignore")
    if isinstance(x, str):
        return sanitize_body(x)
    if isinstance(x, dict):
        out: dict[Any, Any] = {}
        for k, v in x.items():
            ks = str(k).lower()
            if ks in _SENSITIVE_KEYS or "token" in ks or "key" in ks or "pass" in ks or ks.endswith("sid"):
                out[k] = "***"
            else:
                out[k] = scrub_for_log(v)
        return out
    if isinstance(x, (list, tuple)):
        return [scrub_for_log(v) for v in x[:50]]
    return x


# ============================================================
# Input / payload helpers
# ============================================================

def is_magnet(x: str) -> bool:
    return (x or "").strip().lower().startswith("magnet:?")


def is_http_url(x: str) -> bool:
    try:
        u = urlparse((x or "").strip())
        return u.scheme in {"http", "https"} and bool(u.netloc)
    except Exception:
        return False


def host_path(url: str) -> tuple[str, str]:
    try:
        p = urlparse(url)
        host = (p.netloc or "").lower().replace("www.", "")
        path = p.path or ""
        return host, path
    except Exception:
        return "", ""


def payload_items(payload: dict) -> list[str]:
    """
    Accept both:
      {"items":[...]} or {"items":"..."} or {"url":"..."}
    Returns a de-duplicated list preserving order.
    """
    payload = payload or {}
    items = payload.get("items", None)
    url = (payload.get("url") or "").strip()

    out: list[str] = []
    if isinstance(items, list):
        out = [str(x).strip() for x in items if str(x).strip()]
    elif isinstance(items, str) and items.strip():
        out = [items.strip()]
    elif url:
        out = [url]

    seen: set[str] = set()
    uniq: list[str] = []
    for it in out:
        if it not in seen:
            seen.add(it)
            uniq.append(it)
    return uniq


def mk_created(item: str, kind: str, _id: str, name: str, extra: dict | None = None) -> dict:
    d = {"item": redact_url(item), "kind": kind, "id": str(_id), "name": name}
    if extra:
        d.update(extra)
    return d


def mk_error(item: str, err: dict) -> dict:
    return {"item": redact_url(item), "error": err}


def normalize_input_error(_: str) -> dict:
    return {"kind": "bad_request", "code": "UNSUPPORTED_INPUT", "message": "Only magnet or http(s) urls"}


def json_or_none(data: Any, default: Any = None) -> Any:
    """
    Small utility used by status checks (string/json env or bodies).
    """
    if data is None:
        return default
    if isinstance(data, (dict, list)):
        return data
    s = str(data).strip()
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default
