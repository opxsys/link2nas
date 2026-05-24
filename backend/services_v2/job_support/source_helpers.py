import re
import hashlib
from pathlib import Path


def filename_from_path(path: str | None) -> str | None:
    if not path:
        return None

    return str(path).replace("\\", "/").rstrip("/").split("/")[-1] or None


def detect_source_type(value: str) -> str:
    source = str(value or "").strip()

    if source.startswith("magnet:?"):
        return "magnet"

    if re.match(r"^https?://", source, re.IGNORECASE):
        return "direct_link"

    raise ValueError(
        "Invalid source. Must start with magnet:? or http(s)://"
    )


def hash_file(path: str) -> str:
    digest = hashlib.sha256()

    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()
