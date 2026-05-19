from __future__ import annotations

from typing import Any, Dict, Optional

import requests


class RealDebridClientError(Exception):
    pass


class RealDebridAuthError(RealDebridClientError):
    pass


class RealDebridApiError(RealDebridClientError):
    pass


class RealDebridClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token.strip()
        self.timeout = timeout
        self.session = session or requests.Session()

        if not self.token:
            raise RealDebridAuthError("REALDEBRID_TOKEN is empty")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    def _build_url(self, path: str) -> str:
        path = path.strip()
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self.base_url}{path}"

    def _handle_response(self, response):
        if response.status_code >= 400:
            try:
                error_data = response.json()
            except ValueError:
                error_data = {}

            error_code = str(error_data.get("error_code") or "").strip()
            error_message = str(error_data.get("error") or "").strip()
            raw_text = str(response.text or "").strip()

            if response.status_code == 451 and (
                error_message == "infringing_file"
                or error_code == "35"
                or "infringing_file" in raw_text
            ):
                raise RealDebridApiError(
                    "Torrent rejected by RealDebrid: infringing file"
                )

            if error_message:
                raise RealDebridApiError(
                    f"Real-Debrid API error: HTTP {response.status_code} - {error_message}"
                )

            raise RealDebridApiError(
                f"Real-Debrid API error: HTTP {response.status_code} - {raw_text}"
            )

        if response.status_code == 204:
            return None

        if not response.text or not response.text.strip():
            return None

        try:
            return response.json()
        except ValueError as exc:
            raise RealDebridApiError("Invalid JSON response from Real-Debrid") from exc

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = self._build_url(path)

        try:
            response = self.session.get(
                url,
                headers=self._headers(),
                params=params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RealDebridClientError(f"HTTP GET failed: {exc}") from exc

        return self._handle_response(response)


    def _post(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = self._build_url(path)

        try:
            response = self.session.post(
                url,
                headers=self._headers(),
                data=data,
                params=params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RealDebridClientError(f"HTTP POST failed: {exc}") from exc

        return self._handle_response(response)

    def get_user(self, endpoint: str = "/user") -> Dict[str, Any]:
        data = self._get(endpoint)
        if not isinstance(data, dict):
            raise RealDebridApiError("Unexpected /user response format")
        return data

    def add_magnet(self, magnet: str, endpoint: str = "/torrents/addMagnet") -> Dict[str, Any]:
        magnet = magnet.strip()
        if not magnet:
            raise RealDebridClientError("magnet is empty")

        data = self._post(endpoint, data={"magnet": magnet})
        if not isinstance(data, dict):
            raise RealDebridApiError("Unexpected addMagnet response format")
        return data

    def get_torrent_info(
        self,
        torrent_id: str,
        endpoint: str = "/torrents/info",
    ) -> Dict[str, Any]:
        torrent_id = str(torrent_id).strip()
        if not torrent_id:
            raise RealDebridClientError("torrent_id is empty")

        data = self._get(f"{endpoint}/{torrent_id}")
        if not isinstance(data, dict):
            raise RealDebridApiError("Unexpected torrent info response format")
        return data

    def select_files(
        self,
        torrent_id: str,
        files: str,
        endpoint: str = "/torrents/selectFiles",
    ) -> None:
        torrent_id = str(torrent_id).strip()
        files = str(files).strip()

        if not torrent_id:
            raise RealDebridClientError("torrent_id is empty")
        if not files:
            raise RealDebridClientError("files is empty")

        url = self._build_url(f"{endpoint}/{torrent_id}")

        try:
            response = self.session.post(
                url,
                headers=self._headers(),
                data={"files": files},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RealDebridClientError(f"HTTP POST failed: {exc}") from exc

        if response.status_code == 204:
            return

        # 202 = déjà fait
        if response.status_code == 202:
            return

        self._handle_response(response)

        raise RealDebridApiError(
            f"Unexpected response for selectFiles: "
            f"HTTP {response.status_code} - {response.text}"
        )

    def unrestrict_link(
        self,
        link: str,
        endpoint: str = "/unrestrict/link",
    ) -> Dict[str, Any]:
        link = str(link).strip()

        if not link:
            raise RealDebridClientError("link is empty")

        data = self._post(
            endpoint,
            data={"link": link},
        )

        if not isinstance(data, dict):
            raise RealDebridApiError("Unexpected unrestrict_link response format")

        return data

    def add_torrent_file(
        self,
        torrent_file_path: str,
        endpoint: str = "/torrents/addTorrent",
    ) -> Dict[str, Any]:
        torrent_file_path = str(torrent_file_path).strip()
        if not torrent_file_path:
            raise RealDebridClientError("torrent_file_path is empty")

        url = self._build_url(endpoint)

        try:
            with open(torrent_file_path, "rb") as torrent_file:
                file_content = torrent_file.read()

            response = self.session.put(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/x-bittorrent",
                },
                data=file_content,
                timeout=self.timeout,
            )

        except OSError as exc:
            raise RealDebridClientError(f"Cannot read torrent file: {exc}") from exc
        except requests.RequestException as exc:
            raise RealDebridClientError(f"HTTP PUT failed: {exc}") from exc

        data = self._handle_response(response)

        if not isinstance(data, dict):
            raise RealDebridApiError("Unexpected add_torrent_file response format")

        return data

    def unrestrict_folder(
        self,
        link: str,
        endpoint: str = "/unrestrict/folder",
    ) -> list[str]:
        link = str(link).strip()

        if not link:
            raise RealDebridClientError("link is empty")

        data = self._post(
            endpoint,
            data={"link": link},
        )

        if not isinstance(data, list):
            raise RealDebridApiError("Unexpected unrestrict_folder response format")

        return [str(item).strip() for item in data if str(item).strip()]

    def delete_torrent(
        self,
        torrent_id: str,
        endpoint_template: str = "/torrents/delete/{id}",
    ) -> None:
        torrent_id = str(torrent_id).strip()
        if not torrent_id:
            raise RealDebridClientError("torrent_id is empty")

        endpoint = endpoint_template.format(id=torrent_id)
        self._delete(endpoint)

    def delete_download(
        self,
        download_id: str,
        endpoint_template: str = "/downloads/delete/{id}",
    ) -> None:
        download_id = str(download_id).strip()
        if not download_id:
            raise RealDebridClientError("download_id is empty")

        endpoint = endpoint_template.format(id=download_id)
        self._delete(endpoint)

    def _delete(self, endpoint: str) -> Any:
        url = self._build_url(endpoint)

        try:
            response = self.session.delete(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RealDebridClientError(f"HTTP DELETE failed: {exc}") from exc

        return self._handle_response(response)

