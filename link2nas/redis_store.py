# link2nas/redis_store.py
from __future__ import annotations

import json
import time
from typing import Any, Iterable

import redis

# ==============================================================================
# Redis schema (Link2NAS)
#
# Keys
#   - magnet:<id>   : torrent/magnet suivi via AllDebrid
#   - direct:<id>   : lien direct déjà "unlock" (1 fichier) ou batch (N fichiers)
#
# Locks
#   - nas_send_lock:<redis_key>  où redis_key = "magnet:123" ou "direct:abc"
#
# Notes
#   - Toutes les valeurs stockées dans les hash Redis sont des strings.
#   - "links" est une string JSON contenant une liste de dicts :
#         [{"name": "...", "size": 123, "path": "...", "link": "https://..."}, ...]
# ==============================================================================


# ==============================================================================
# App statuses (stockés dans "app_status")
# ==============================================================================
APP_STATUS_DISPLAY_READY = "display_ready"
APP_STATUS_NAS_PENDING = "nas_pending"
APP_STATUS_NAS_SENT = "nas_sent"
APP_STATUS_NAS_FAILED = "nas_failed"
APP_STATUS_NAS_DISABLED = "nas_disabled"

# ==============================================================================
# NAS errors (codes normalisés)
# ==============================================================================
NAS_ERROR_NO_LINKS = "NO_LINKS"
NAS_ERROR_NAS_DISABLED = "NAS_DISABLED"


# ==============================================================================
# Key helpers / decoding
# ==============================================================================
def redis_key_id(key: str) -> tuple[str, str]:
    """Retourne (kind, id) à partir de 'magnet:123' / 'direct:abc'."""
    k = (key or "").strip()
    if k.startswith("magnet:"):
        return "magnet", k.split("magnet:", 1)[1]
    if k.startswith("direct:"):
        return "direct", k.split("direct:", 1)[1]
    return "unknown", k


def decode_hash(data: dict) -> dict[str, str]:
    """
    Convertit un dict issu de HGETALL (bytes->str).
    Redis renvoie souvent {b'k': b'v'}.
    """
    out: dict[str, str] = {}
    for k, v in (data or {}).items():
        kk = k.decode("utf-8", "ignore") if isinstance(k, (bytes, bytearray)) else str(k)
        vv = v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else str(v)
        out[kk] = vv
    return out


def parse_links_dicts(decoded: dict[str, str]) -> list[dict[str, Any]]:
    """
    Parse le champ "links" (JSON) d'un item redis décodé.
    Ne retourne que des dicts contenant au moins "link".
    """
    raw = decoded.get("links", "[]") or "[]"
    try:
        links = json.loads(raw)
        if not isinstance(links, list):
            return []
    except Exception:
        return []

    out: list[dict[str, Any]] = []
    for x in links:
        if isinstance(x, dict) and str(x.get("link") or "").strip():
            out.append(x)
    return out


# ==============================================================================
# Scans / listings
# ==============================================================================
def iter_redis_keys_scan(client: redis.Redis, pattern: str, count: int = 1000) -> Iterable[bytes]:
    """
    Générateur de clés via SCAN (évite KEYS).
    Retourne des bytes (comportement redis-py).
    """
    cursor = 0
    while True:
        cursor, keys = client.scan(cursor=cursor, match=pattern, count=count)
        for k in keys:
            yield k
        if cursor == 0:
            break


def iter_all_items_keys(client: redis.Redis) -> list[bytes]:
    """Liste toutes les clés métier (magnet:* + direct:*)."""
    keys: list[bytes] = []
    keys.extend(list(iter_redis_keys_scan(client, "magnet:*", count=2000)))
    keys.extend(list(iter_redis_keys_scan(client, "direct:*", count=2000)))
    return keys


# ==============================================================================
# Soft-delete
# ==============================================================================
def is_deleted(client: redis.Redis, key: bytes | str) -> bool:
    """True si l'item est marqué deleted=1."""
    try:
        v = client.hget(key, "deleted")
        if v is None:
            return False
        s = v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else str(v)
        return s.strip() == "1"
    except Exception:
        return False


def mark_deleted(client: redis.Redis, key: str, name: str, kind: str) -> None:
    """
    Marque un item comme supprimé (soft delete).
    On conserve le minimum utile pour debug/audit.
    """
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


# ==============================================================================
# NAS send lock (anti-concurrence / anti-doublons)
# ==============================================================================
def acquire_nas_send_lock(client: redis.Redis, lock_id: str, ttl_seconds: int = 900) -> bool:
    """
    Lock distribué simple (SET NX EX).
    lock_id attendu = redis_key ("magnet:123" / "direct:abc").
    """
    lock_key = f"nas_send_lock:{lock_id}"
    return bool(client.set(lock_key, "1", nx=True, ex=int(ttl_seconds)))


def release_nas_send_lock(client: redis.Redis, lock_id: str) -> None:
    """Libère le lock nas_send_lock:<lock_id>."""
    try:
        client.delete(f"nas_send_lock:{lock_id}")
    except Exception:
        pass


# ==============================================================================
# Storage primitives
# ==============================================================================
def _now() -> str:
    """Timestamp Unix en string (convention stockage Redis)."""
    return str(time.time())


def store_magnet(client: redis.Redis, magnet_id: int, name: str, app_status: str) -> None:
    """
    Initialise un item magnet:<id>.
    Le détail (status/progress/links/...) est mis à jour par le poller.
    """
    client.hset(
        f"magnet:{int(magnet_id)}",
        mapping={
            "name": (name or "").strip() or "magnet",
            "status": "pending",
            "app_status": app_status,
            "size": "0",
            "downloaded": "0",
            "progress": "0",
            "timestamp": _now(),
            "type": "magnet",
            # Champs de génération / unlock
            "links_raw": "[]",
            "links_total": "0",
            "unlock_offset": "0",
            "links": "[]",
            "links_count": "0",
            "unlock_progress": "0",
            # NAS tracking
            "sent_to_nas": "false",
            "sent_to_nas_at": "",
            "nas_error": "",
            "nas_last_attempt": "",
            "nas_folder": "",
            "ds_dest_mode": "",
        },
    )


def store_direct(
    client: redis.Redis,
    direct_id: str,
    filename: str,
    filesize: int,
    unlocked_link: str,
    app_status: str,
    *,
    sent_to_nas: bool = False,
    nas_error: str = "",
    source_url: str = "",
    source_domain: str = "",
    is_batch: bool = False,
) -> None:
    """
    Stocke un item direct:<id> contenant 1 seul fichier (cas standard).
    """
    fn = (filename or "").strip() or "file"
    sz = int(filesize or 0)
    now = _now()

    client.hset(
        f"direct:{direct_id}",
        mapping={
            "name": fn,
            "status": "ready",
            "app_status": app_status,
            "size": str(sz),
            "downloaded": str(sz),
            "progress": "100",
            "timestamp": now,
            "type": "direct",
            "links": json.dumps([{"name": fn, "size": sz, "path": fn, "link": unlocked_link}]),
            "links_count": "1",
            # NAS tracking
            "sent_to_nas": "true" if sent_to_nas else "false",
            "sent_to_nas_at": now if sent_to_nas else "",
            "nas_error": nas_error or "",
            "nas_last_attempt": now,
            "nas_folder": "",
            # Source metadata (optionnel)
            "source_url": source_url or "",
            "source_domain": source_domain or "",
            "is_batch": "1" if is_batch else "0",
            "ds_dest_mode": "",
        },
    )


def store_direct_batch(
    client: redis.Redis,
    direct_id: str,
    name: str,
    unlocked_items: list[dict],
    app_status: str,
    *,
    sent_to_nas: bool = False,
    nas_error: str = "",
    source_url: str = "",
    source_domain: str = "",
) -> None:
    """
    Stocke un item direct:<id> contenant N fichiers (batch).
    unlocked_items = liste de payloads AllDebrid (unlock_link_safe)
    """
    links: list[dict[str, Any]] = []
    total_size = 0

    for it in (unlocked_items or []):
        if not isinstance(it, dict):
            continue

        url = str(it.get("link") or "").strip()
        if not url:
            continue

        fn = str(it.get("filename") or it.get("name") or "file").strip() or "file"
        sz = int(it.get("filesize") or it.get("size") or 0)

        links.append({"name": fn, "size": sz, "path": fn, "link": url})
        total_size += sz

    now = _now()

    client.hset(
        f"direct:{direct_id}",
        mapping={
            "name": (name or "").strip() or "batch",
            "status": "ready",
            "app_status": app_status,
            "size": str(int(total_size)),
            "downloaded": str(int(total_size)),
            "progress": "100",
            "timestamp": now,
            "type": "direct",
            "links": json.dumps(links),
            "links_count": str(len(links)),
            # NAS tracking
            "sent_to_nas": "true" if sent_to_nas else "false",
            "sent_to_nas_at": now if sent_to_nas else "",
            "nas_error": nas_error or "",
            "nas_last_attempt": now,
            "nas_folder": "",
            # Source metadata (optionnel)
            "source_url": source_url or "",
            "source_domain": source_domain or "",
            "is_batch": "1",
            "ds_dest_mode": "",
        },
    )


# ==============================================================================
# NAS folder persistence (retry-friendly)
# ==============================================================================
def get_nas_folder(client: redis.Redis, redis_key: str) -> str:
    """
    Retourne le dossier NAS (relatif DSM_DESTINATION_BASE) associé à un item.
    Stocké dans la hash de l'item (magnet:<id> / direct:<id>).
    """
    try:
        v = client.hget(redis_key, "nas_folder")
        if v is None:
            return ""
        return v.decode("utf-8", "ignore").strip() if isinstance(v, (bytes, bytearray)) else str(v).strip()
    except Exception:
        return ""


def set_nas_folder(client: redis.Redis, redis_key: str, folder: str) -> None:
    """Enregistre le dossier NAS associé à un item."""
    try:
        client.hset(redis_key, mapping={"nas_folder": (folder or "").strip()})
    except Exception:
        pass
