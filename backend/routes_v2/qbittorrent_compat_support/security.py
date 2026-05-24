import hashlib


def _safe_input_hash(value: str | bytes | None) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="ignore")

    return hashlib.sha256(raw).hexdigest()[:16]


def _safe_source_summary(value: str | None) -> dict:
    raw = str(value or "").strip()

    if not raw:
        return {
            "input_type": "empty",
            "input_hash": None,
        }

    if raw.startswith("magnet:?"):
        return {
            "input_type": "magnet",
            "input_hash": _safe_input_hash(raw),
        }

    if raw.startswith("http://") or raw.startswith("https://"):
        return {
            "input_type": "url",
            "input_hash": _safe_input_hash(raw),
        }

    return {
        "input_type": "unknown",
        "input_hash": _safe_input_hash(raw),
    }


def _friendly_qbit_error(exc: Exception) -> str:
    return str(exc)
