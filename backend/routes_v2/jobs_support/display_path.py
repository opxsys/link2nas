from pathlib import Path


def local_display_path(
    destination_path: str | None,
    destination_name: str | None,
    destination_type: str | None,
    user_id: str | None,
    userdata_dir: str | None,
) -> str | None:
    """Return a user-safe relative display path for local destinations.

    Strips <userdata_dir>/<user_id>/local/ via Path.relative_to() so the API
    never exposes internal server paths to clients.  Accepts 'local' in either
    destination_name OR destination_type.  Non-local destinations (Synology/NAS)
    are returned unchanged.  Falls back to the original value on any mismatch.
    """
    if not destination_path:
        return None
    dest_name = (destination_name or "").lower().strip()
    dest_type = (destination_type or "").lower().strip()
    if dest_name != "local" and dest_type != "local":
        return destination_path
    if not userdata_dir or not user_id:
        return destination_path
    try:
        local_root = Path(userdata_dir).resolve() / str(user_id) / "local"
        relative = Path(destination_path).relative_to(local_root)
        return str(relative)
    except ValueError:
        return destination_path
