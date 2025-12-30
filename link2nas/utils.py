from __future__ import annotations

import re
from urllib.parse import urlparse


def is_magnet(s: str) -> bool:
    return (s or "").strip().lower().startswith("magnet:?")


def is_http_url(s: str) -> bool:
    try:
        u = urlparse((s or "").strip())
        return u.scheme in {"http", "https"} and bool(u.netloc)
    except Exception:
        return False


def sanitize_body(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if len(s) > 800:
        s = s[:800] + "…(truncated)"
    s = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", r"\1***", s)
    s = re.sub(
        r'(?i)("?(?:api[_-]?key|token|access[_-]?token|refresh[_-]?token|password|passwd|sid)"?\s*:\s*)"([^"]*)"',
        r'\1"***"',
        s,
    )
    s = re.sub(
        r"(?i)((?:api[_-]?key|token|access[_-]?token|refresh[_-]?token|password|passwd|sid)\s*=\s*)([^&\s]+)",
        r"\1***",
        s,
    )
    s = re.sub(r"(?i)magnet:\?[^ \r\n\t\"']+", "magnet:?***", s)
    s = re.sub(r"(?i)\bhttps?://[^\s\"']+", "https://***", s)
    return s.replace("\r", "\\r").replace("\n", "\\n")
