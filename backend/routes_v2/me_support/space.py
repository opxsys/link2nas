import secrets
from pathlib import Path

from backend.utils.time import utc_now_iso

_now = utc_now_iso


def _get_or_create_public_slug(user, user_repo) -> str:
    if user.public_slug:
        return user.public_slug
    slug = secrets.token_urlsafe(24)
    user.public_slug = slug
    user.updated_at = _now()
    user_repo.update(user)
    return slug


def _user_space_path(user_id: str, settings) -> Path:
    userdata_root = Path(settings.USERDATA_DIR).resolve()
    space_path = (userdata_root / user_id / "local").resolve()
    try:
        space_path.relative_to(userdata_root)
    except ValueError:
        raise ValueError("Resolved user space escapes userdata directory")
    return space_path
