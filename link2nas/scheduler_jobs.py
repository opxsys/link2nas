# link2nas/scheduler_jobs.py
from __future__ import annotations

import logging
import time

import redis

from . import redis_store as rs
from .synology import send_to_download_station_safe

logger = logging.getLogger("link2nas.scheduler")


def check_pending_torrents(s, rdb: redis.Redis) -> None:
    """
    - cherche les magnets nas_pending
    - tente l’envoi NAS UNE FOIS par item
    - respecte les locks Redis
    """

    if not s.nas_enabled:
        return

    keys = rs.iter_all_items_keys(rdb)

    for key in keys:
        key_str = key.decode("utf-8") if isinstance(key, (bytes, bytearray)) else str(key)

        data = rs.decode_hash(rdb.hgetall(key))
        if not data:
            continue

        if data.get("app_status") != rs.APP_STATUS_NAS_PENDING:
            continue

        if rs.is_deleted(rdb, key):
            continue

        # liens
        links = rs.parse_links_dicts(data)
        urls = [x["link"] for x in links if isinstance(x, dict) and x.get("link")]

        if not urls:
            rdb.hset(
                key,
                mapping={
                    "app_status": rs.APP_STATUS_NAS_FAILED,
                    "sent_to_nas": "false",
                    "nas_error": rs.NAS_ERROR_NO_LINKS,
                    "nas_last_attempt": str(time.time()),
                },
            )
            continue

        # LOCK = clé redis complète (pas juste l’id)
        if not rs.acquire_nas_send_lock(rdb, lock_id=key_str, ttl_seconds=900):
            continue

        try:
            ok, err = send_to_download_station_safe(s, urls)

            if ok:
                rdb.hset(
                    key,
                    mapping={
                        "app_status": rs.APP_STATUS_NAS_SENT,
                        "sent_to_nas": "true",
                        "sent_to_nas_at": str(time.time()),
                        "nas_error": "",
                        "nas_last_attempt": str(time.time()),
                    },
                )
                logger.info("[NAS] sent OK %s (%d links)", key_str, len(urls))
            else:
                rdb.hset(
                    key,
                    mapping={
                        "app_status": rs.APP_STATUS_NAS_FAILED,
                        "sent_to_nas": "false",
                        "nas_error": f"{err.get('code')}: {err.get('message')}",
                        "nas_last_attempt": str(time.time()),
                    },
                )
                logger.warning("[NAS] failed %s: %s", key_str, err)

        finally:
            rs.release_nas_send_lock(rdb, lock_id=key_str)
