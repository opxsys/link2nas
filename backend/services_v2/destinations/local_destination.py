from pathlib import Path
import shutil
import requests

from .utils import (
    is_multi_output,
    ensure_local_parent,
    format_bytes_human,
)

class LocalDownloadCancelled(Exception):
    pass

class LocalDestination:

    def __init__(self, userdata_root: str, user_id: str, base_path: str):
        self.userdata_root = Path(userdata_root)
        self.user_id = str(user_id)
        self.relative_base_path = self._clean_relative_path(base_path or "downloads")

        self.base_path = (
            self.userdata_root
            / self.user_id
            / "local"
            / self.relative_base_path
        ).resolve()

        self._ensure_inside_userdata()

    def ensure_enough_space(
        self,
        output_links,
        margin_percent: int = 10,
        min_free_bytes: int = 1024 * 1024 * 1024,
    ) -> dict:
        self.base_path.mkdir(parents=True, exist_ok=True)

        required_bytes = self._required_bytes(output_links)

        if required_bytes <= 0:
            raise ValueError("Cannot start local download: unknown total size")

        usage = shutil.disk_usage(self.base_path)
        required_with_margin = int(required_bytes * (1 + (margin_percent / 100)))
        required_total = required_with_margin + int(min_free_bytes)

        if usage.free < required_total:
            raise ValueError(
                "Not enough disk space for local download "
                f"(required={format_bytes_human(required_total)}, "
                f"free={format_bytes_human(usage.free)})"
            )
        return {
            "required_bytes": required_bytes,
            "required_with_margin": required_with_margin,
            "min_free_bytes": min_free_bytes,
            "free_bytes": usage.free,
        }

    def send(self, output_links, cancel_check=None, progress_callback=None):
        if not output_links:
            raise Exception("No output links")

        multi = is_multi_output(output_links)

        if not multi:
            link = output_links[0]

            filename = self._safe_filename(link.get("filename") or "download.bin")
            target = self._unique_path((self.base_path / filename).resolve())

            self._ensure_inside_userdata(target)
            ensure_local_parent(target)

            self._download(
                link["url"],
                target,
                cancel_check=cancel_check,
                progress_callback=progress_callback,
            )

            return {
                "destination": "local",
                "status": "completed",
                "destination_path": str(target),
            }

        root_path = self._resolve_multi_root_path(output_links)

        for link in output_links:

            if cancel_check and cancel_check():
                raise LocalDownloadCancelled("Local download cancelled")

            relative = (
                link.get("relative_path")
                or link.get("path")
                or link.get("filename")
                or "download.bin"
            )
            safe_relative = self._clean_relative_path(relative)
            target = (root_path / self._strip_root_folder(safe_relative)).resolve()
            self._ensure_inside_userdata(target)
            ensure_local_parent(target)

            self._download(
                link["url"],
                target,
                cancel_check=cancel_check,
                progress_callback=progress_callback,
            )

        return {
            "destination": "local",
            "status": "completed",
            "destination_path": str(root_path),
        }

    def test_connection(self):
        self.base_path.mkdir(parents=True, exist_ok=True)

        test_file = self.base_path / ".link2nas_write_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)

        return {
            "ok": True,
            "destination_name": "local",
            "message": "Local destination is writable.",
        }

    def _download(self, url, path: Path, cancel_check=None, progress_callback=None):
        part_path = path.with_name(path.name + ".part")

        try:
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()

                total_size = int(r.headers.get("Content-Length") or 0)
                downloaded = 0

                with open(part_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if cancel_check and cancel_check():
                            raise LocalDownloadCancelled("Local download cancelled")

                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                            if progress_callback:
                                progress_callback(len(chunk), downloaded, total_size)

                part_path.replace(path)

        except Exception:
            part_path.unlink(missing_ok=True)
            raise

    def _required_bytes(self, output_links) -> int:
        total = 0

        for link in output_links:
            size = link.get("filesize") or link.get("bytes") or link.get("size")

            if size is None:
                return 0

            try:
                size = int(size)
            except (TypeError, ValueError):
                return 0

            if size <= 0:
                return 0

            total += size

        return total

    def _clean_relative_path(self, value: str) -> Path:
        raw = str(value or "").strip().replace("\\", "/").strip("/")

        if not raw:
            raw = "downloads"

        candidate = Path(raw)

        if candidate.is_absolute():
            raise ValueError("Local destination path must be relative")

        clean_parts = []

        for part in candidate.parts:
            part = part.strip()

            if not part or part in {".", ".."}:
                raise ValueError("Invalid local destination path")

            clean_parts.append(self._safe_filename(part))

        return Path(*clean_parts)

    def _safe_filename(self, value: str) -> str:
        raw = str(value or "").strip().replace("\\", "_").replace("/", "_")

        forbidden = '<>:"|?*'
        for char in forbidden:
            raw = raw.replace(char, "")

        raw = raw.strip().strip(".")

        if not raw:
            return "download.bin"

        return raw[:120]

    def _unique_path(self, path: Path) -> Path:
        if not path.exists() and not path.with_name(path.name + ".part").exists():
            return path

        parent = path.parent
        stem = path.stem
        suffix = path.suffix

        index = 1

        while True:
            candidate = parent / f"{stem} ({index}){suffix}"
            part_candidate = candidate.with_name(candidate.name + ".part")

            if not candidate.exists() and not part_candidate.exists():
                return candidate.resolve()

            index += 1


    def _unique_dir_path(self, path: Path) -> Path:
        if not path.exists():
            return path

        parent = path.parent
        name = path.name
        index = 1

        while True:
            candidate = parent / f"{name} ({index})"

            if not candidate.exists():
                return candidate.resolve()

            index += 1


    def _resolve_multi_root_path(self, output_links) -> Path:
        first_relative = None

        for link in output_links:
            first_relative = (
                link.get("relative_path")
                or link.get("path")
                or link.get("filename")
            )

            if first_relative:
                break

        if not first_relative:
            return self._unique_dir_path((self.base_path / "job").resolve())

        safe_relative = self._clean_relative_path(first_relative)
        parts = safe_relative.parts

        if len(parts) <= 1:
            return self._unique_dir_path((self.base_path / "job").resolve())

        root_name = parts[0]
        root_path = (self.base_path / root_name).resolve()

        self._ensure_inside_userdata(root_path)

        return self._unique_dir_path(root_path)


    def _strip_root_folder(self, relative_path: Path) -> Path:
        parts = relative_path.parts

        if len(parts) <= 1:
            return relative_path

        return Path(*parts[1:])

    def _ensure_inside_userdata(self, path: Path | None = None) -> None:
        root = self.userdata_root.resolve()
        target = (path or self.base_path).resolve()

        try:
            target.relative_to(root)
        except ValueError:
            raise ValueError("Resolved local destination escapes userdata directory")