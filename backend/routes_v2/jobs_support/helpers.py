import json
from pathlib import Path


def _bool_from_form(value) -> bool:
    return str(value or "false").strip().lower() in {"1", "true", "yes", "on"}


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def _parse_json_object(value):
    try:
        if not value:
            return None
        parsed = json.loads(value) if isinstance(value, str) else value
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _filename_from_path(path):
    if not path:
        return None
    return str(path).replace("\\", "/").rstrip("/").split("/")[-1] or None
