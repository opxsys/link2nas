from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import requests


class AllDebridClientError(Exception):
    pass


class AllDebridAuthError(AllDebridClientError):
    pass


class AllDebridApiError(AllDebridClientError):
    pass


_AUTH_ERROR_CODES = {
    "AUTH_MISSING_APIKEY",
    "AUTH_BAD_APIKEY",
    "AUTH_BLOCKED",
    "AUTH_USER_BANNED",
    "ACCOUNT_INVALID",
    "NO_SERVER",
    "MAGNET_MUST_BE_PREMIUM",
    "MUST_BE_PREMIUM",
}

_ERROR_MESSAGES = {
    "AUTH_MISSING_APIKEY": "AllDebrid API key missing",
    "AUTH_BAD_APIKEY": "AllDebrid API key invalid",
    "AUTH_BLOCKED": "AllDebrid API key blocked",
    "AUTH_USER_BANNED": "AllDebrid account banned",
    "ACCOUNT_INVALID": "AllDebrid account has no access to this endpoint",
    "NO_SERVER": "AllDebrid refuses this server or VPN endpoint",
    "MAINTENANCE": "AllDebrid is under maintenance",
    "LINK_IS_MISSING": "No link provided",
    "BAD_LINK": "Link is invalid",
    "LINK_HOST_NOT_SUPPORTED": "Host or link not supported",
    "LINK_DOWN": "Link is unavailable on the host website",
    "LINK_PASS_PROTECTED": "Link is password protected",
    "LINK_HOST_UNAVAILABLE": "Host temporarily unavailable",
    "LINK_TOO_MANY_DOWNLOADS": "Too many concurrent downloads for this host",
    "LINK_HOST_FULL": "AllDebrid host servers are full",
    "LINK_HOST_LIMIT_REACHED": "Host download limit reached",
    "LINK_ERROR": "Could not unlock this link",
    "LINK_TEMPORARY_UNAVAILABLE": "Link temporarily unavailable",
    "LINK_NOT_SUPPORTED": "Link not supported for this host",
    "REDIRECTOR_NOT_SUPPORTED": "Redirector not supported",
    "REDIRECTOR_ERROR": "Could not extract redirected links",
    "FREE_TRIAL_LIMIT_REACHED": "Free trial limit reached",
    "MUST_BE_PREMIUM": "Premium account required",
    "MAGNET_INVALID_ID": "Magnet ID is invalid or expired",
    "MAGNET_INVALID_URI": "Magnet is invalid",
    "MAGNET_INVALID_FILE": "Torrent file is invalid",
    "MAGNET_FILE_UPLOAD_FAILED": "Torrent file upload failed",
    "MAGNET_NO_URI": "No magnet provided",
    "MAGNET_PROCESSING": "Magnet is already processing or completed",
    "MAGNET_TOO_MANY_ACTIVE": "Too many active magnets on AllDebrid",
    "MAGNET_TOO_MANY": "Global AllDebrid magnet limit reached",
    "MAGNET_MUST_BE_PREMIUM": "Premium account required for magnets",
    "MAGNET_TOO_LARGE": "Torrent is too large",
    "MAGNET_UPLOAD_FAILED": "Magnet upload failed",
    "MAGNET_INTERNAL_ERROR": "Internal AllDebrid magnet error",
    "MAGNET_CANT_BOOTSTRAP": "Magnet could not start downloading in time",
    "MAGNET_MAGNET_TOO_BIG": "Torrent is larger than AllDebrid limit",
    "MAGNET_TOOK_TOO_LONG": "Torrent download exceeded AllDebrid time limit",
    "MAGNET_LINKS_REMOVED": "Torrent files were removed from hoster side",
    "MAGNET_PROCESSING_FAILED": "Torrent processing failed",
}


class AllDebridClient:
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
            raise AllDebridAuthError("ALLDEBRID_TOKEN is empty")

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

    def _raise_api_error(
        self,
        code: Optional[str],
        message: Optional[str],
        *,
        status_code: Optional[int] = None,
    ) -> None:
        code_value = str(code or "").strip().upper() or None
        message_value = str(message or "").strip() or None

        if not message_value and code_value:
            message_value = _ERROR_MESSAGES.get(code_value)

        if not message_value:
            if status_code is not None:
                message_value = f"AllDebrid API error HTTP {status_code}"
            else:
                message_value = "AllDebrid API error"

        rendered = (
            f"AllDebrid API error: code={code_value} message={message_value}"
            if code_value
            else f"AllDebrid API error: message={message_value}"
        )

        if status_code in {401, 403, 429} or code_value in _AUTH_ERROR_CODES:
            raise AllDebridAuthError(rendered)

        raise AllDebridApiError(rendered)

    def _handle_response(self, response: requests.Response, *, context: Optional[str] = None) -> Any:
        try:
            payload = response.json()
        except ValueError as exc:
            content_type = response.headers.get("Content-Type", "")
            body_preview = response.text[:300].replace("\n", " ").replace("\r", " ").strip()

            # AllDebrid sometimes returns HTTP 500 + empty body for fake/invalid torrent upload.
            if (
                context == "torrent_file_upload"
                and response.status_code == 500
                and not body_preview
            ):
                raise AllDebridApiError(
                    "AllDebrid API error: code=MAGNET_INVALID_FILE message=Torrent file is invalid"
                ) from exc

            raise AllDebridApiError(
                f"Invalid JSON response from AllDebrid: HTTP {response.status_code}, "
                f"content_type={content_type or 'unknown'}, "
                f"body={body_preview or '<empty>'}"
            ) from exc

        if response.status_code >= 400:
            code = None
            message = None
            if isinstance(payload, dict):
                error_payload = payload.get("error") or {}
                if isinstance(error_payload, dict):
                    code = error_payload.get("code")
                    message = error_payload.get("message") or error_payload.get("details")
            self._raise_api_error(code, message, status_code=response.status_code)

        if isinstance(payload, dict) and payload.get("status") == "error":
            error_payload = payload.get("error") or {}
            if isinstance(error_payload, dict):
                code = error_payload.get("code")
                message = error_payload.get("message") or error_payload.get("details")
            else:
                code = None
                message = str(error_payload or "").strip() or None
            self._raise_api_error(code, message)

        return payload

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None, *, context: Optional[str] = None) -> Any:
        url = self._build_url(path)
        try:
            response = self.session.get(
                url,
                headers=self._headers(),
                params=params,
                timeout=self.timeout,
            )
        except requests.Timeout as exc:
            raise AllDebridClientError(f"AllDebrid timeout: {exc}") from exc
        except requests.RequestException as exc:
            raise AllDebridClientError(f"HTTP GET failed: {exc}") from exc

        return self._handle_response(response, context=context)

    def _post(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        *,
        context: Optional[str] = None,
    ) -> Any:
        url = self._build_url(path)
        try:
            response = self.session.post(
                url,
                headers=self._headers(),
                data=data,
                json=json,
                files=files,
                timeout=self.timeout,
            )
        except requests.Timeout as exc:
            raise AllDebridClientError(f"AllDebrid timeout: {exc}") from exc
        except requests.RequestException as exc:
            raise AllDebridClientError(f"HTTP POST failed: {exc}") from exc

        return self._handle_response(response, context=context)

    def get_user(self) -> Dict[str, Any]:
        data = self._get("/v4.1/user")
        if not isinstance(data, dict):
            raise AllDebridApiError("Unexpected user response format")
        return data

    def add_magnet(self, magnet: str) -> Dict[str, Any]:
        magnet = magnet.strip()
        if not magnet:
            raise AllDebridClientError("magnet is empty")

        data = self._post("/v4/magnet/upload", data={"magnets[]": magnet})
        if not isinstance(data, dict):
            raise AllDebridApiError("Unexpected magnet upload response format")
        return data

    def add_torrent_file(self, path: str) -> Dict[str, Any]:
        torrent_path = Path(str(path).strip())
        if not str(torrent_path):
            raise AllDebridClientError("path is empty")
        if not torrent_path.exists():
            raise AllDebridClientError(f"torrent file not found: {torrent_path}")
        if not torrent_path.is_file():
            raise AllDebridClientError(f"torrent path is not a file: {torrent_path}")

        with torrent_path.open("rb") as file_handle:
            data = self._post(
                "/v4/magnet/upload/file",
                files={
                    "files[]": (
                        torrent_path.name,
                        file_handle,
                        "application/x-bittorrent",
                    )
                },
                context="torrent_file_upload",
            )

        if not isinstance(data, dict):
            raise AllDebridApiError("Unexpected torrent file upload response format")
        return data

    def get_torrent_info(self, torrent_id: str) -> Dict[str, Any]:
        torrent_id = str(torrent_id).strip()
        if not torrent_id:
            raise AllDebridClientError("torrent_id is empty")

        data = self._post("/v4.1/magnet/status", data={"id": torrent_id})
        if not isinstance(data, dict):
            raise AllDebridApiError("Unexpected magnet status response format")
        return data

    def select_files(self, torrent_id: str, files: str) -> None:
        torrent_id = str(torrent_id).strip()
        files = str(files).strip()

        if not torrent_id:
            raise AllDebridClientError("torrent_id is empty")
        if not files:
            raise AllDebridClientError("files is empty")

        self._post("/v4/magnet/files", data={"id[]": torrent_id, "files[]": files})

    def unrestrict_link(self, link: str) -> Dict[str, Any]:
        link = str(link).strip()
        if not link:
            raise AllDebridClientError("link is empty")

        data = self._post("/v4/link/unlock", data={"link": link})
        if not isinstance(data, dict):
            raise AllDebridApiError("Unexpected link unlock response format")
        return data

    def delete_torrent(self, torrent_id: str) -> None:
        torrent_id = str(torrent_id).strip()
        if not torrent_id:
            raise AllDebridClientError("torrent_id is empty")

        self._post("/v4/magnet/delete", data={"id": torrent_id})

    def delete_download(self, download_id: str) -> None:
        return