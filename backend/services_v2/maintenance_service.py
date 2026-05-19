from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path


class MaintenanceService:
    def __init__(self, *, settings, db, app_settings_service=None):
        self.settings = settings
        self.db = db
        self._app_settings_service = app_settings_service

    def now_iso(self) -> str:
        return datetime.now(UTC).isoformat()

    def _get_effective_public_base_url(self) -> str:
        env_url = getattr(self.settings, "PUBLIC_BASE_URL", "")
        if self._app_settings_service is not None:
            return self._app_settings_service.get_effective_public_base_url(
                env_fallback=env_url
            )
        return env_url

    def get_status(self) -> dict:
        paths = self._check_paths()
        disk = self._check_disk()
        db_status = self._check_database()

        checks = [db_status, *paths]
        overall_ok = all(bool(item.get("ok")) for item in checks)

        return {
            "ok": overall_ok,
            "generated_at": self.now_iso(),
            "app": {
                "name": self._app_settings_service.get_effective_app_name(
                    env_fallback=getattr(self.settings, "APP_NAME", "")
                ) if self._app_settings_service else getattr(self.settings, "APP_NAME", "link2nas"),
                "tagline": self._app_settings_service.get_effective_app_tagline(
                    env_fallback=getattr(self.settings, "APP_TAGLINE", "")
                ) if self._app_settings_service else getattr(self.settings, "APP_TAGLINE", ""),
                "version": getattr(self.settings, "APP_VERSION", "unknown"),
                "debug": bool(getattr(self.settings, "DEBUG", False)),
                "public_base_url": self._get_effective_public_base_url(),
            },
            "database": {
                "backend": getattr(self.settings, "V2_DATABASE_BACKEND", "unknown"),
                **db_status,
            },
            "paths": paths,
            "disk": disk,
        }

    def _check_database(self) -> dict:
        try:
            with self.db.connect() as conn:
                cursor = conn.execute("SELECT 1")
                row = cursor.fetchone()

            value = None
            if row is not None:
                if isinstance(row, dict):
                    value = row.get("1") or row.get("?column?")
                else:
                    value = row[0]

            return {
                "ok": str(value) == "1",
                "message": "Database accessible",
            }
        except Exception as exc:
            return {
                "ok": False,
                "message": f"Database check failed: {exc}",
            }

    def _check_paths(self) -> list[dict]:
        candidates = [
            ("data", getattr(self.settings, "DATA_DIR", None), True),
            ("tmp", getattr(self.settings, "TEMP_DIR", None), True),
            ("userdata", getattr(self.settings, "USERDATA_DIR", None), True),
            ("logs", getattr(self.settings, "LOG_DIR", None), True),
            ("torrents_temp_internal", getattr(self.settings, "TORRENT_DIR", None), True),
        ]
        results = []

        for name, raw_path, required in candidates:
            if not raw_path:
                results.append({
                    "name": name,
                    "path": None,
                    "required": required,
                    "exists": False,
                    "is_dir": False,
                    "writable": False,
                    "ok": not required,
                    "message": "Path not configured" if required else "Optional path not configured",
                })
                continue

            path = Path(raw_path).resolve()
            exists = path.exists()
            is_dir = path.is_dir()
            writable = False
            message = "OK"

            try:
                if exists and is_dir:
                    test_file = path / ".link2nas_write_test"
                    test_file.write_text("ok", encoding="utf-8")
                    test_file.unlink(missing_ok=True)
                    writable = True
                elif exists and not is_dir:
                    message = "Path exists but is not a directory"
                else:
                    message = "Path does not exist"
            except Exception as exc:
                message = f"Write check failed: {exc}"

            ok = exists and is_dir and writable

            results.append({
                "name": name,
                "path": str(path),
                "required": required,
                "exists": exists,
                "is_dir": is_dir,
                "writable": writable,
                "ok": ok if required else (ok or not exists),
                "message": message,
            })

        return results

    def _check_disk(self) -> dict:
        base_path = Path(getattr(self.settings, "DATA_DIR", ".")).resolve()

        try:
            usage = shutil.disk_usage(base_path)
            percent_used = round((usage.used / usage.total) * 100, 2) if usage.total else 0
            percent_free = round((usage.free / usage.total) * 100, 2) if usage.total else 0

            return {
                "ok": usage.free > 0,
                "path": str(base_path),
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent_used": percent_used,
                "percent_free": percent_free,
                "message": "Disk space readable",
            }
        except Exception as exc:
            return {
                "ok": False,
                "path": str(base_path),
                "total_bytes": 0,
                "used_bytes": 0,
                "free_bytes": 0,
                "percent_used": 0,
                "percent_free": 0,
                "message": f"Disk check failed: {exc}",
            }
