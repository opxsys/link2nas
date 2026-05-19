from __future__ import annotations

from typing import Any

from backend.services_v2.providers.base import Provider

class AllDebridProvider(Provider):
    provider_name = "alldebrid"

    def __init__(self, client: AllDebridClient) -> None:
        self.client = client

    def get_user(self) -> dict[str, Any]:
        return self.client.get_user()

    def add_magnet(self, magnet: str) -> dict[str, Any]:
        raw = self.client.add_magnet(magnet)
        data = raw.get("data") or {}
        magnets = data.get("magnets") or []
        magnet_info = self._extract_first_upload_item(magnets, item_name="magnet")
        return {"id": magnet_info.get("id")}

    def add_torrent_file(self, path: str) -> dict[str, Any]:
        raw = self.client.add_torrent_file(path)
        data = raw.get("data") or {}
        files = data.get("files") or []
        file_info = self._extract_first_upload_item(files, item_name="torrent file")
        return {"id": file_info.get("id")}

    def get_torrent_info(self, torrent_id: str) -> dict[str, Any]:
        raw = self.client.get_torrent_info(torrent_id)
        data = raw.get("data") or {}
        magnets = data.get("magnets")

        magnet_info = None

        if isinstance(magnets, list):
            if magnets:
                magnet_info = magnets[0]
        elif isinstance(magnets, dict):
            if "id" in magnets and "statusCode" in magnets:
                magnet_info = magnets
            elif magnets:
                first_value = next(iter(magnets.values()))
                if isinstance(first_value, dict):
                    magnet_info = first_value

        if not isinstance(magnet_info, dict):
            raise AllDebridApiError("AllDebrid returned no valid magnet info")

        status_code = magnet_info.get("statusCode")
        status_label = self._map_status(status_code)

        flat_files = self._flatten_ad_entries(magnet_info.get("files") or [])

        links = []
        files = []

        for index, entry in enumerate(flat_files, start=1):
            link_value = str(entry.get("link") or "").strip()
            if link_value:
                links.append(link_value)

            files.append(
                {
                    "id": index,
                    "path": entry.get("path") or f"file_{index}",
                    "bytes": entry.get("bytes"),
                    "selected": 1,
                }
            )

        raw_size = magnet_info.get("size")
        raw_downloaded = magnet_info.get("downloaded")

        try:
            size = int(raw_size) if raw_size is not None else 0
            downloaded = int(raw_downloaded) if raw_downloaded is not None else 0

            if status_label == "downloaded":
                progress = 100
            elif size > 0 and downloaded > 0:
                progress = max(0, min(99, int((downloaded / size) * 100)))
            else:
                progress = 0
        except (TypeError, ValueError, ZeroDivisionError):
            progress = 100 if status_label == "downloaded" else 0

        return {
            "status": status_label,
            "filename": magnet_info.get("filename") or magnet_info.get("name"),
            "bytes": magnet_info.get("size"),
            "progress": progress,
            "links": links,
            "files": files,
        }

    def select_files(self, torrent_id: str, files: str) -> None:
        self.client.select_files(torrent_id, files)

    def unrestrict_link(self, link: str) -> dict[str, Any]:
        raw = self.client.unrestrict_link(link)
        data = raw.get("data") or {}
        return {
            "download": data.get("link"),
            "filename": data.get("filename"),
            "filesize": data.get("filesize"),
            "id": data.get("id"),
        }

    def delete_torrent(self, torrent_id: str) -> None:
        self.client.delete_torrent(torrent_id)

    def delete_download(self, download_id: str) -> None:
        self.client.delete_download(download_id)

    @staticmethod
    def _flatten_ad_entries(entries, parent_path: str = "") -> list[dict[str, Any]]:
        flattened = []

        for entry in entries or []:
            if not isinstance(entry, dict):
                continue

            name = str(entry.get("n") or "unnamed").strip() or "unnamed"
            current_path = f"{parent_path}/{name}" if parent_path else name

            nested_entries = entry.get("e")
            if isinstance(nested_entries, list):
                flattened.extend(AllDebridProvider._flatten_ad_entries(nested_entries, current_path))
                continue

            flattened.append(
                {
                    "path": current_path,
                    "bytes": entry.get("s"),
                    "link": entry.get("l"),
                }
            )

        return flattened

    @staticmethod
    def _extract_first_upload_item(items: Any, *, item_name: str) -> dict[str, Any]:
        if not isinstance(items, list) or not items:
            raise AllDebridApiError(f"Unexpected AllDebrid {item_name} upload response")

        first_item = items[0]
        if not isinstance(first_item, dict):
            raise AllDebridApiError(f"Unexpected AllDebrid {item_name} upload item format")

        error_payload = first_item.get("error")
        if isinstance(error_payload, dict):
            code = error_payload.get("code")
            message = error_payload.get("message") or error_payload.get("details") or "unknown"
            raise AllDebridApiError(f"AllDebrid API error: code={code} message={message}")

        item_id = first_item.get("id")
        if not item_id:
            raise AllDebridApiError(f"AllDebrid {item_name} upload returned no id")

        return first_item

    @staticmethod
    def _map_status(status_code: Any) -> str:
        try:
            code = int(status_code)
        except (TypeError, ValueError):
            return "error"

        if code == 0:
            return "queued"
        if code == 1:
            return "downloading"
        if code == 2:
            return "magnet_conversion"
        if code == 3:
            return "uploading"
        if code == 4:
            return "downloaded"
        if code in {5, 6, 7, 8, 9, 10, 11, 12, 13, 14}:
            return "error"

        return "error"
