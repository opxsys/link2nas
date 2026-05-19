from __future__ import annotations

from typing import Any

from backend.services_v2.providers.base import Provider

class RealDebridProvider(Provider):
    provider_name = "realdebrid"

    def __init__(self, client: RealDebridClient) -> None:
        self.client = client

    def get_user(self) -> dict[str, Any]:
        return self.client.get_user()

    def add_magnet(self, magnet: str) -> dict[str, Any]:
        return self.client.add_magnet(magnet)

    def add_torrent_file(self, path: str) -> dict[str, Any]:
        return self.client.add_torrent_file(path)

    def get_torrent_info(self, torrent_id: str) -> dict[str, Any]:
        return self.client.get_torrent_info(torrent_id)

    def select_files(self, torrent_id: str, files: str) -> None:
        self.client.select_files(torrent_id, files)

    def unrestrict_link(self, link: str) -> dict[str, Any]:
        return self.client.unrestrict_link(link)

    def delete_torrent(self, torrent_id: str) -> None:
        self.client.delete_torrent(torrent_id)

    def delete_download(self, download_id: str) -> None:
        self.client.delete_download(download_id)
