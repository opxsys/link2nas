from pathlib import Path
from uuid import uuid4

from flask import current_app
from werkzeug.utils import secure_filename


def _save_uploaded_torrent(uploaded_file) -> str:
    settings = current_app.config["SETTINGS"]

    temp_dir = Path(settings.TEMP_DIR)
    temp_dir.mkdir(parents=True, exist_ok=True)

    filename = str(uploaded_file.filename or "").strip()
    safe_name = secure_filename(filename) or "upload.torrent"

    saved_path = temp_dir / f"{uuid4().hex}_{safe_name}"
    uploaded_file.save(saved_path)

    return str(saved_path)


def _safe_unlink(path: str | None) -> None:
    if not path:
        return

    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass
