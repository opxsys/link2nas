# link2nas/web_process.py
from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

import redis
from flask import g

from . import redis_store as rs
from .alldebrid import generate_links_safe, upload_magnet_safe
from .config import Settings
from .nas_send import send_item_to_nas_safe
from .web_helpers import (
    host_path,
    is_http_url,
    is_magnet,
    mk_created,
    normalize_input_error,
    redact_url,
    scrub_for_log,
)


class WebProcessor:
    """
    Centralize "submit item" logic for webapp routes & API routes.

    This module owns:
    - process_one_item_public()
    - process_one_item_admin()
    - direct send path (lock + Redis status)
    - storage rules for direct vs batch direct
    """

    def __init__(self, s: Settings, rdb: redis.Redis, logger: logging.Logger):
        self.s = s
        self.rdb = rdb
        self.log = logger

    # ============================================================
    # NAS helpers (direct send)
    # ============================================================

    def _mark_nas_state(self, key: str, *, status: str, sent: bool, nas_error: str = "") -> None:
        mapping = {
            "app_status": status,
            "sent_to_nas": "true" if sent else "false",
            "nas_error": nas_error,
            "nas_last_attempt": str(time.time()),
        }
        if sent:
            mapping["sent_to_nas_at"] = str(time.time())
        self.rdb.hset(key, mapping=mapping)

    def send_direct_now(self, direct_id: str) -> tuple[bool, dict | None]:
        """
        Immediate NAS send for direct:<id>.
        - honors feature flag
        - uses lock to avoid concurrent double-send
        - updates Redis state
        """
        key = f"direct:{direct_id}"

        if not self.s.nas_enabled:
            self._mark_nas_state(
                key,
                status=rs.APP_STATUS_NAS_DISABLED,
                sent=False,
                nas_error=rs.NAS_ERROR_NAS_DISABLED,
            )
            return False, {"code": rs.NAS_ERROR_NAS_DISABLED, "message": "NAS disabled"}

        if not rs.acquire_nas_send_lock(self.rdb, key, ttl_seconds=900):
            return True, None  # send already in progress

        try:
            ok, err = send_item_to_nas_safe(self.s, self.rdb, key)
            if ok:
                self._mark_nas_state(key, status=rs.APP_STATUS_NAS_SENT, sent=True, nas_error="")
                return True, None

            code = (err or {}).get("code") or "NAS_SEND_FAILED"
            msg = (err or {}).get("message") or "send_failed"
            self._mark_nas_state(key, status=rs.APP_STATUS_NAS_FAILED, sent=False, nas_error=f"{code}: {msg}")
            return False, {"code": code, "message": msg}
        finally:
            rs.release_nas_send_lock(self.rdb, key)

    # ============================================================
    # Storage helpers
    # ============================================================

    def _store_direct(
        self,
        *,
        item: str,
        direct_id: str,
        filename: str,
        filesize: int,
        unlocked_link: str,
        for_admin_send: bool,
        source_url: str = "",
    ) -> tuple[dict | None, dict | None, int | None]:
        if for_admin_send:
            rs.store_direct(
                self.rdb,
                direct_id,
                filename,
                filesize,
                unlocked_link,
                app_status=rs.APP_STATUS_NAS_PENDING,
                sent_to_nas=False,
                nas_error="",
                source_url=source_url or "",
                source_domain=(urlparse(source_url).netloc or "").lower().replace("www.", "") if source_url else "",
                is_batch=False,
            )
            ok_nas, err_nas = self.send_direct_now(direct_id)
            extra = {"nas": ("sent" if ok_nas else "failed")}
            if (not ok_nas) and err_nas:
                extra["nas_error"] = f"{err_nas.get('code')}: {err_nas.get('message')}"
            return mk_created(item, "direct", direct_id, filename, extra), None, None

        rs.store_direct(
            self.rdb,
            direct_id,
            filename,
            filesize,
            unlocked_link,
            app_status=rs.APP_STATUS_DISPLAY_READY,
            source_url=source_url or "",
            source_domain=(urlparse(source_url).netloc or "").lower().replace("www.", "") if source_url else "",
            is_batch=False,
        )
        return mk_created(item, "direct", direct_id, filename, {"link_ready": True}), None, None

    def _store_direct_batch(
        self,
        *,
        item: str,
        direct_id: str,
        batch_name: str,
        links: list[dict],
        for_admin_send: bool,
        source_url: str,
    ) -> tuple[dict | None, dict | None, int | None]:
        src_domain = (urlparse(source_url).netloc or "batch").lower().replace("www.", "")

        if for_admin_send:
            rs.store_direct_batch(
                self.rdb,
                direct_id,
                batch_name,
                links,
                app_status=rs.APP_STATUS_NAS_PENDING,
                sent_to_nas=False,
                nas_error="",
                source_url=source_url,
                source_domain=src_domain,
            )
            ok_nas, err_nas = self.send_direct_now(direct_id)
            extra = {"links_count": len(links), "nas": ("sent" if ok_nas else "failed")}
            if (not ok_nas) and err_nas:
                extra["nas_error"] = f"{err_nas.get('code')}: {err_nas.get('message')}"
            return mk_created(item, "direct", direct_id, batch_name, extra), None, None

        rs.store_direct_batch(
            self.rdb,
            direct_id,
            batch_name,
            links,
            app_status=rs.APP_STATUS_DISPLAY_READY,
            source_url=source_url,
            source_domain=src_domain,
        )
        return mk_created(item, "direct", direct_id, batch_name, {"links_count": len(links)}), None, None

    # ============================================================
    # Public processing
    # ============================================================

    def process_one_item_public(self, item: str):
        rid = getattr(g, "rid", "--------")

        self.log.info(
            "[RID %s][PROCESS_PUBLIC] start item_len=%d is_magnet=%s is_http=%s",
            rid,
            len(item or ""),
            is_magnet(item),
            is_http_url(item),
        )

        if is_magnet(item):
            self.log.info("[RID %s][PROCESS_PUBLIC] magnet -> upload_magnet_safe()", rid)
            ok, data_or_err = upload_magnet_safe(self.s, item)
            if not ok:
                self.log.warning(
                    "[RID %s][PROCESS_PUBLIC] magnet upload FAILED err=%s",
                    rid,
                    scrub_for_log(data_or_err),
                )
                return None, data_or_err, 422

            mid = data_or_err["id"]
            name = data_or_err["name"]
            rs.store_magnet(self.rdb, mid, name, app_status="")
            self.log.info("[RID %s][PROCESS_PUBLIC] magnet stored key=magnet:%s name=%r", rid, mid, name)
            return mk_created(item, "magnet", str(mid), name), None, None

        if is_http_url(item):
            url = item.strip()
            host, path = host_path(url)
            self.log.info("[RID %s][PROCESS_PUBLIC] http url domain=%r path=%r", rid, host, path[:120])

            ok, res_or_err = generate_links_safe(self.s, self.rdb, url)
            if not ok:
                self.log.warning(
                    "[RID %s][PROCESS_PUBLIC] generate_links_safe FAILED err=%s",
                    rid,
                    scrub_for_log(res_or_err),
                )
                return None, res_or_err if isinstance(res_or_err, dict) else {"code": "GEN_FAILED", "message": "generate failed"}, 422

            links = res_or_err.get("links") or []
            links_count = int(res_or_err.get("links_count") or 0)

            if links_count > 1:
                direct_id = str(int(time.time() * 1000))
                batch_name = (res_or_err.get("redirector") or "batch").strip() or "batch"
                self.log.info(
                    "[RID %s][PROCESS_PUBLIC] batch direct stored id=%s name=%r links=%d",
                    rid,
                    direct_id,
                    batch_name,
                    links_count,
                )
                return self._store_direct_batch(
                    item=item,
                    direct_id=direct_id,
                    batch_name=batch_name,
                    links=links,
                    for_admin_send=False,
                    source_url=url,
                )

            if not links:
                return None, {"code": "NO_LINKS", "message": "no direct link produced"}, 422

            one = links[0] or {}
            unlocked_link = (one.get("link") or "").strip()
            filename = (one.get("filename") or "").strip() or "direct_link"
            filesize = int(one.get("filesize") or 0)
            direct_id = str(int(time.time() * 1000))

            self.log.info(
                "[RID %s][PROCESS_PUBLIC] direct stored id=%s filename=%r size=%d link_domain=%r",
                rid,
                direct_id,
                filename,
                filesize,
                host_path(unlocked_link)[0],
            )

            return self._store_direct(
                item=item,
                direct_id=direct_id,
                filename=filename,
                filesize=filesize,
                unlocked_link=unlocked_link,
                for_admin_send=False,
                source_url=url,
            )

        self.log.warning("[RID %s][PROCESS_PUBLIC] unsupported input item=%s", rid, redact_url(item))
        return None, normalize_input_error(item), 400

    # ============================================================
    # Admin processing
    # ============================================================

    def process_one_item_admin(self, item: str):
        rid = getattr(g, "rid", "--------")

        self.log.info(
            "[RID %s][PROCESS_ADMIN] start item_len=%d is_magnet=%s is_http=%s nas_enabled=%s",
            rid,
            len(item or ""),
            is_magnet(item),
            is_http_url(item),
            bool(self.s.nas_enabled),
        )

        if is_magnet(item):
            self.log.info("[RID %s][PROCESS_ADMIN] magnet -> upload_magnet_safe()", rid)
            ok, data_or_err = upload_magnet_safe(self.s, item)
            if not ok:
                self.log.warning(
                    "[RID %s][PROCESS_ADMIN] magnet upload FAILED err=%s",
                    rid,
                    scrub_for_log(data_or_err),
                )
                return None, data_or_err, 422

            mid = data_or_err["id"]
            name = data_or_err["name"]
            rs.store_magnet(self.rdb, mid, name, app_status=rs.APP_STATUS_NAS_PENDING)
            self.log.info(
                "[RID %s][PROCESS_ADMIN] magnet stored key=magnet:%s name=%r app_status=nas_pending",
                rid,
                mid,
                name,
            )
            return mk_created(item, "magnet", str(mid), name, {"nas": "scheduled"}), None, None

        if is_http_url(item):
            if not self.s.nas_enabled:
                self.log.warning("[RID %s][PROCESS_ADMIN] NAS disabled -> forbid direct send", rid)
                return None, {
                    "kind": "forbidden",
                    "code": rs.NAS_ERROR_NAS_DISABLED,
                    "message": "NAS disabled by configuration",
                }, 403

            url = item.strip()
            host, path = host_path(url)
            self.log.info("[RID %s][PROCESS_ADMIN] http url domain=%r path=%r", rid, host, path[:120])

            ok, res_or_err = generate_links_safe(self.s, self.rdb, url)
            if not ok:
                self.log.warning(
                    "[RID %s][PROCESS_ADMIN] generate_links_safe FAILED err=%s",
                    rid,
                    scrub_for_log(res_or_err),
                )
                return None, res_or_err if isinstance(res_or_err, dict) else {"code": "GEN_FAILED", "message": "generate failed"}, 422

            links = res_or_err.get("links") or []
            links_count = int(res_or_err.get("links_count") or 0)

            if links_count > 1:
                direct_id = str(int(time.time() * 1000))
                batch_name = (res_or_err.get("redirector") or "batch").strip() or "batch"
                self.log.info(
                    "[RID %s][PROCESS_ADMIN] batch direct stored id=%s name=%r links=%d",
                    rid,
                    direct_id,
                    batch_name,
                    links_count,
                )
                return self._store_direct_batch(
                    item=item,
                    direct_id=direct_id,
                    batch_name=batch_name,
                    links=links,
                    for_admin_send=True,
                    source_url=url,
                )

            if not links:
                return None, {"code": "NO_LINKS", "message": "no direct link produced"}, 422

            one = links[0] or {}
            unlocked_link = (one.get("link") or "").strip()
            filename = (one.get("filename") or "").strip() or "direct_link"
            filesize = int(one.get("filesize") or 0)
            direct_id = str(int(time.time() * 1000))

            self.log.info(
                "[RID %s][PROCESS_ADMIN] direct stored id=%s filename=%r size=%d link_domain=%r",
                rid,
                direct_id,
                filename,
                filesize,
                host_path(unlocked_link)[0],
            )

            return self._store_direct(
                item=item,
                direct_id=direct_id,
                filename=filename,
                filesize=filesize,
                unlocked_link=unlocked_link,
                for_admin_send=True,
                source_url=url,
            )

        self.log.warning("[RID %s][PROCESS_ADMIN] unsupported input item=%s", rid, redact_url(item))
        return None, normalize_input_error(item), 400
