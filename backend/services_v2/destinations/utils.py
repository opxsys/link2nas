import os
from pathlib import Path


def is_multi_output(output_links):
    if not output_links:
        return False
    return len(output_links) > 1


def build_job_folder_name(job):
    short_id = str(job.id)[:8]
    name = (job.filename or "job").strip()
    safe = "".join(c for c in name if c.isalnum() or c in " .-_").strip()
    return f"{safe}_{short_id}"


def build_relative_path(file_entry):
    path = file_entry.get("path") or file_entry.get("filename")
    if not path:
        return f"file_{file_entry.get('id')}"
    return path.replace("\\", "/")


def ensure_local_parent(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)

def format_bytes_human(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]

    size = float(value)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"

        size /= 1024