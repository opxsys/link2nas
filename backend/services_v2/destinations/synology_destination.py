from typing import Any
import requests
import re
import json
import unicodedata

from backend.services_v2.destinations.base import Destination


class SynologyDestinationError(Exception):
    pass


class SynologyDestination(Destination):
    def __init__(
        self,
        synology_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        destination_base: str | None = None,
    ):
        self.synology_url = synology_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.destination_base = (destination_base or "").strip().strip("/")


    def send(self, output_links: list[dict[str, Any]]) -> dict[str, Any]:
        if not output_links:
            raise SynologyDestinationError("No output links to send")

        http = requests.Session()
        fs_sid = None
        ds_sid = None
        created = 0
        results = []

        try:
            ds_sid = self._login(http, "DownloadStation")

            is_multi = len(output_links) > 1

            if is_multi:
                fs_sid = self._login(http, "FileStation")

            for item in output_links:
                url = item.get("url")
                if not url:
                    continue

                destination_rel = self.destination_base

                if is_multi:
                    relative_path = (
                        item.get("relative_path")
                        or item.get("path")
                        or item.get("filename")
                    )
                    parent_folder = self._parent_folder(relative_path)

                    parent_abs = self._absolute_path(self.destination_base, parent_folder)
                    self._ensure_folder(http, fs_sid, parent_abs)

                    destination_rel = self._relative_path(self.destination_base, parent_folder)

                result = self._create_download_task(http, ds_sid, url, destination_rel)
                results.append(result)
                created += 1

            if created == 0:
                raise SynologyDestinationError("No NAS task created")

            return {
                "destination": "synology",
                "status": "completed",
                "tasks_created": created,
                "destination_path": self.destination_base,
                "results": results,
            }

        finally:
            if fs_sid:
                self._logout(http, fs_sid, "FileStation")
            if ds_sid:
                self._logout(http, ds_sid, "DownloadStation")
            http.close()


    def test_connection(self) -> dict[str, Any]:
        http = requests.Session()
        ds_sid = None
        fs_sid = None

        try:
            ds_sid = self._login(http, "DownloadStation")

            resp = http.post(
                f"{self.synology_url}/webapi/DownloadStation/task.cgi",
                data={
                    "api": "SYNO.DownloadStation.Task",
                    "version": "1",
                    "method": "list",
                    "offset": 0,
                    "limit": 1,
                    "_sid": ds_sid,
                },
                timeout=15,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
            result = resp.json()

            if not result.get("success"):
                code = (result.get("error") or {}).get("code")
                raise SynologyDestinationError(f"NAS Download Station test failed (code={code})")

            root = self._extract_destination_root()
            if root:
                fs_sid = self._login(http, "FileStation")
                self._check_destination_root(http, fs_sid, root)

            return {
                "ok": True,
                "destination_name": "synology",
                "message": "NAS login and Download Station API OK",
            }

        finally:
            if fs_sid:
                self._logout(http, fs_sid, "FileStation")
            if ds_sid:
                self._logout(http, ds_sid, "DownloadStation")
            http.close()

    def _extract_destination_root(self) -> str | None:
        """Return the first non-empty segment of destination_base, or None."""
        if not self.destination_base:
            return None
        parts = [p for p in str(self.destination_base).strip("/").split("/") if p]
        return parts[0] if parts else None

    def _check_destination_root(self, http: requests.Session, fs_sid: str, root: str) -> None:
        """Raise SynologyDestinationError if the root shared folder is not accessible."""
        try:
            resp = http.post(
                f"{self.synology_url}/webapi/entry.cgi",
                data={
                    "api": "SYNO.FileStation.List",
                    "version": "2",
                    "method": "list",
                    "folder_path": f"/{root}",
                    "limit": 1,
                    "_sid": fs_sid,
                },
                timeout=15,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise SynologyDestinationError(
                f"NAS destination root not accessible root={root} http error: {exc}"
            ) from exc

        try:
            data = resp.json()
        except ValueError:
            raise SynologyDestinationError(
                f"NAS destination root not accessible root={root} invalid JSON"
            )

        if not data.get("success"):
            code = (data.get("error") or {}).get("code")
            raise SynologyDestinationError(
                f"NAS destination root not accessible root={root} code={code}"
            )

    def _login(self, http: requests.Session, session: str) -> str:
        resp = http.post(
            f"{self.synology_url}/webapi/auth.cgi",
            data={
                "api": "SYNO.API.Auth",
                "version": "3",
                "method": "login",
                "account": self.username,
                "passwd": self.password,
                "session": session,
                "format": "sid",
            },
            timeout=15,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        data = resp.json()

        if not data.get("success"):
            code = (data.get("error") or {}).get("code")
            raise SynologyDestinationError(f"NAS {session} login failed (code={code})")

        sid = (data.get("data") or {}).get("sid")
        if not sid:
            raise SynologyDestinationError(f"NAS {session} login succeeded but SID is missing")

        return str(sid)

    def _logout(self, http: requests.Session, sid: str, session: str) -> None:
        try:
            http.post(
                f"{self.synology_url}/webapi/auth.cgi",
                data={
                    "api": "SYNO.API.Auth",
                    "version": "3",
                    "method": "logout",
                    "session": session,
                    "_sid": sid,
                },
                timeout=10,
                verify=self.verify_ssl,
            )
        except Exception:
            pass

    def _ensure_folder(self, http: requests.Session, sid: str, path_abs: str | None) -> None:
        if not path_abs:
            return

        parts = [p for p in str(path_abs).strip("/").split("/") if p]

        if len(parts) <= 1:
            return

        # Le premier segment est le dossier partagé, ex: /downloads.
        # Il existe déjà. On ne le crée jamais.
        current = parts[0]

        for part in parts[1:]:
            parent = f"/{current}"
            name = part
            self._create_folder(http, sid, parent, name)
            current = f"{current}/{part}"

    def _create_folder(self, http: requests.Session, sid: str, parent: str, name: str) -> None:
        name = self._safe_path_part(name)

        try:
            resp = http.post(
                f"{self.synology_url}/webapi/entry.cgi",
                data={
                    "api": "SYNO.FileStation.CreateFolder",
                    "version": "2",
                    "method": "create",
                    "folder_path": parent,
                    "name": json.dumps([name], ensure_ascii=False),
                    "force_parent": "true",
                    "_sid": sid,
                },
                timeout=20,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise SynologyDestinationError(
                f"NAS folder creation HTTP error parent={parent} name={name}: {exc}"
            ) from exc

        try:
            data = resp.json()
        except ValueError as exc:
            raise SynologyDestinationError(
                f"NAS folder creation returned invalid JSON parent={parent} name={name}"
            ) from exc

        if data.get("success"):
            return

        error = data.get("error") or {}
        code = error.get("code")
        nested_errors = error.get("errors") or []

        # V1 behavior: dossier déjà existant / conflit non bloquant.
        if code in {407, 414, 1100}:
            return

        for nested in nested_errors:
            nested_code = nested.get("code")
            if nested_code in {407, 414, 1100}:
                return

        raise SynologyDestinationError(
            f"NAS folder creation failed code={code} parent={parent} name={name} data={data}"
        )

    def _create_download_task(
        self,
        http: requests.Session,
        sid: str,
        url: str,
        destination_rel: str | None,
    ) -> dict[str, Any]:
        payload = {
            "api": "SYNO.DownloadStation.Task",
            "version": "1",
            "method": "create",
            "uri": url,
            "_sid": sid,
        }

        if destination_rel:
            payload["destination"] = destination_rel.strip("/")

        resp = http.post(
            f"{self.synology_url}/webapi/DownloadStation/task.cgi",
            data=payload,
            timeout=30,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        data = resp.json()

        if not data.get("success"):
            code = (data.get("error") or {}).get("code")
            raise SynologyDestinationError(
                f"NAS task creation failed code={code} destination={destination_rel}"
            )

        return data

    def _parent_folder(self, relative_path: str | None) -> str | None:
        if not relative_path:
            return None

        raw_parts = [
            p for p in str(relative_path).replace("\\", "/").split("/")
            if p
        ]

        if len(raw_parts) <= 1:
            return None

        parts = [self._safe_path_part(p) for p in raw_parts[:-1]]
        parts = [p for p in parts if p]

        if not parts:
            return None

        return "/".join(parts)

    def _absolute_path(self, *parts) -> str | None:
        rel = self._relative_path(*parts)
        if not rel:
            return None
        return "/" + rel.strip("/")

    def _relative_path(self, *parts) -> str | None:
        clean = [str(p).strip("/") for p in parts if p]
        if not clean:
            return None
        return "/".join(clean)

    def _safe_path_part(self, value: str) -> str:
        value = str(value or "").strip()
        value = unicodedata.normalize("NFKC", value)

        value = value.replace("/", "_").replace("\\", "_")
        value = re.sub(r'[<>:"|?*\[\]]', "", value)
        value = re.sub(r"\s+", " ", value).strip()

        value = self._truncate_utf8(value, max_bytes=255)

        if not value or value in {".", ".."}:
            return "job"

        return value

    def _truncate_utf8(self, value: str, max_bytes: int) -> str:
        encoded = value.encode("utf-8")

        if len(encoded) <= max_bytes:
            return value

        truncated = encoded[:max_bytes]

        while True:
            try:
                return truncated.decode("utf-8")
            except UnicodeDecodeError:
                truncated = truncated[:-1]