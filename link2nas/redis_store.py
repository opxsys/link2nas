from __future__ import annotations

import json
import time
from typing import Iterable

import redis

# Conventions
# - magnets: magnet:<id>
# - directs: direct:<id>
# - lock: nas_send_lock:<redis_key>  (redis_key = "magnet:123" / "direct:abc")

APP_STATUS_DISPLAY_READY = "display_ready"
APP_STATUS_NAS_PENDING = "nas_pending"
APP_STATUS_NAS_SENT = "nas_sent"
APP_STATUS_NAS_FAILED = "nas_failed"
APP_STATUS_NAS_DISABLED = "nas_disabled"

NAS_ERROR_NO_LINKS = "NO_LINKS"
NAS_ERROR_NAS_DISABLED = "NAS_DISABLED"


def redis_key_id(key: str) -> tuple[str, str]:
    key = (key or "").strip()
    if key.startswith("magnet:"):
        return "magnet", key.split("magnet:", 1)[1]
    if key.startswith("direct:"):
        return "direct", key.split("direct:", 1)[1]
    return "unknown", key


def decode_hash(data: dict) -> dict:
    return {
        (k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)): (
            v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
        )
        for k, v in (data or {}).items()
    }


def parse_links_dicts(decoded: dict) -> list[dict]:
    try:
        links = json.loads(decoded.get("links", "[]") or "[]")
        if not isinstance(links, list):
            return []
    except Exception:
        return []

    out = []
    for x in links:
        if isinstance(x, dict) and str(x.get("link") or "").strip():
            out.append(x)
    return out


def iter_redis_keys_scan(client: redis.Redis, pattern: str, count: int = 1000) -> Iterable[bytes]:
    cursor = 0
    while True:
        cursor, keys = client.scan(cursor=cursor, match=pattern, count=count)
        for k in keys:
            yield k
        if cursor == 0:
            break


def iter_all_items_keys(client: redis.Redis) -> list[bytes]:
    keys: list[bytes] = []
    keys.extend(list(iter_redis_keys_scan(client, "magnet:*", count=2000)))
    keys.extend(list(iter_redis_keys_scan(client, "direct:*", count=2000)))
    return keys


def is_deleted(client: redis.Redis, key: bytes | str) -> bool:
    try:
        v = client.hget(key, "deleted")
        v = (v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else (v or "")).strip()
        return v == "1"
    except Exception:
        return False


def mark_deleted(client: redis.Redis, key: str, name: str, kind: str) -> None:
    try:
        client.hset(
            key,
            mapping={
                "deleted": "1",
                "deleted_at": str(time.time()),
                "name": (name or "inconnu").strip() or "inconnu",
                "type": (kind or "unknown").strip() or "unknown",
            },
        )
    except Exception:
        pass


def acquire_nas_send_lock(client: redis.Redis, lock_id: str, ttl_seconds: int = 900) -> bool:
    lock_key = f"nas_send_lock:{lock_id}"
    return bool(client.set(lock_key, "1", nx=True, ex=ttl_seconds))


def release_nas_send_lock(client: redis.Redis, lock_id: str) -> None:
    lock_key = f"nas_send_lock:{lock_id}"
    try:
        client.delete(lock_key)
    except Exception:
        pass


def store_magnet(client: redis.Redis, magnet_id: int, name: str, app_status: str) -> None:
    client.hset(
        f"magnet:{int(magnet_id)}",
        mapping={
            "name": name,
            "status": "pending",
            "app_status": app_status,
            "size": "0",
            "downloaded": "0",
            "progress": "0",
            "timestamp": str(time.time()),
            "type": "magnet",
            "links_raw": "[]",
            "links_total": "0",
            "unlock_offset": "0",
            "links": "[]",
            "links_count": "0",
            "unlock_progress": "0",
            "sent_to_nas": "false",
            "sent_to_nas_at": "",
            "nas_error": "",
            "nas_last_attempt": "",
        },
    )


def store_direct(
    client: redis.Redis,
    direct_id: str,
    filename: str,
    filesize: int,
    unlocked_link: str,
    app_status: str,
    sent_to_nas: bool = False,
    nas_error: str = "",
) -> None:
    client.hset(
        f"direct:{direct_id}",
        mapping={
            "name": filename,
            "status": "ready",
            "app_status": app_status,
            "size": str(int(filesize or 0)),
            "downloaded": str(int(filesize or 0)),
            "progress": "100",
            "timestamp": str(time.time()),
            "type": "direct",
            "links": json.dumps(
                [
                    {
                        "name": filename,
                        "size": int(filesize or 0),
                        "path": filename,
                        "link": unlocked_link,
                    }
                ]
            ),
            "links_count": "1",
            "sent_to_nas": "true" if sent_to_nas else "false",
            "sent_to_nas_at": str(time.time()) if sent_to_nas else "",
            "nas_error": nas_error or "",
            "nas_last_attempt": str(time.time()),
        },
    )