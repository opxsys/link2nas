
# link2nas/scheduler_jobs.py

"""
Scheduler Link2NAS

Règles :
- Un magnet est TERMINÉ dès que links_count > 0
- Les liens AllDebrid ne sont PAS stockés unlockés
- Les URLs sont unlockées JUSTE AVANT envoi NAS
- status = état AllDebrid
- app_status = workflow NAS
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import redis

from . import redis_store as rs
from .alldebrid import get_magnet_files_safe, get_magnet_status_safe, unlock_link_safe
from .synology import send_to_download_station_safe


logger = logging.getLogger("link2nas.scheduler")


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(float(x))
    except Exception:
        return default


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _build_links_from_ad_files(files: list[dict]) -> tuple[list[dict], int]:
    """
    AllDebrid magnet/files peut renvoyer:
      - liste plate: [{n,s,l}, ...]
      - OU liste de dossiers: [{n, e:[{n,s,l}, ...]}, ...]
    On aplati tout en links[].
    Retourne (links, total_size).
    """
    links: list[dict] = []
    total_size = 0

    def push_file(f: dict):
        nonlocal total_size
        if not isinstance(f, dict):
            return
        link = (f.get("l") or f.get("link") or "").strip()
        if not link:
            return
        name = (f.get("n") or f.get("name") or "").strip() or "file"
        size = _safe_int(f.get("s") or f.get("size") or 0, 0)
        links.append({"name": name, "size": size, "path": name, "link": link})
        total_size += size

    for item in files or []:
        if not isinstance(item, dict):
            continue

        # cas dossier: item["e"] = liste d'entrées
        entries = item.get("e")
        if isinstance(entries, list):
            for f in entries:
                push_file(f)
            continue

        # cas plat: item est déjà un fichier
        push_file(item)

    return links, total_size


def _refresh_one_magnet_from_alldebrid(s, rdb: redis.Redis, key: str, magnet_id: str) -> None:
    """
    Rafraîchit status/progress/links d'un magnet:
      - magnet/status (optionnel)
      - magnet/files (utile)
    """

    # IMPORTANT: si les liens sont déjà générés, statut terminal => on ne touche plus au status/progress AD
    # Sinon AllDebrid peut renvoyer "ready" et écraser ton "completed".
    try:
        existing_links_count = _safe_int((rdb.hget(key, "links_count") or b"0").decode("utf-8", "ignore"), 0)
    except Exception:
        existing_links_count = 0

    if existing_links_count > 0:
        return

    # 1) status/progress (best-effort)
    ok_st, st_or_err = get_magnet_status_safe(s, magnet_id)
    if ok_st and isinstance(st_or_err, dict):
        st = st_or_err
        mapping = {}

        ad_status = (st.get("status") or "").strip().lower()
        if ad_status:
            mapping["status"] = ad_status

        if st.get("progress") is not None:
            mapping["progress"] = str(_safe_float(st.get("progress"), 0.0))

        if st.get("size") is not None:
            mapping["size"] = str(_safe_int(st.get("size"), 0))

        if st.get("downloaded") is not None:
            mapping["downloaded"] = str(_safe_int(st.get("downloaded"), 0))

        # unlock_progress = même valeur que progress côté UI (sinon ça reste à 0)
        if "progress" in mapping:
            mapping["unlock_progress"] = mapping["progress"]

        if mapping:
            rdb.hset(key, mapping=mapping)

    # 2) files -> links
    ok_files, files_or_err = get_magnet_files_safe(s, magnet_id)
    if not ok_files:
        err = files_or_err or {}
        code = (err.get("code") or "AD_MAGNET_FILES_FAILED")
        msg = (err.get("message") or "magnet/files failed")
        rdb.hset(
            key,
            mapping={
                "nas_error": f"{code}: {msg}",
                "nas_last_attempt": str(time.time()),
            },
        )
        return

    files = files_or_err if isinstance(files_or_err, list) else []
    links, total_size = _build_links_from_ad_files(files)

    # On garde une trace brute (debug)
    mapping = {
        "links_raw": json.dumps(files or []),
        "nas_last_attempt": str(time.time()),
    }

    if links:
        mapping.update(
            {
                "links": json.dumps(links),
                "links_count": str(len(links)),
                "links_total": str(len(links)),
                "size": str(total_size),
                "downloaded": str(total_size),
                "unlock_progress": "100",
                "progress": "100",
                "status": "completed",
                "nas_error": "",
            }
        )
    else:
        # Pas de liens dispo: on reste pending
        mapping.update(
            {
                "links": "[]",
                "links_count": "0",
                "links_total": "0",
                "unlock_progress": "0",
                "status": (rdb.hget(key, "status") or b"pending").decode("utf-8", "ignore") or "pending",
            }
        )

    rdb.hset(key, mapping=mapping)


def refresh_pending_magnets(s, rdb: redis.Redis, max_per_run: int = 30) -> int:
    """
    - cherche les magnets avec links_count=0
    - rafraîchit via AllDebrid
    Retourne le nombre de magnets où on a obtenu >=1 lien.
    """
    updated = 0
    processed = 0

    for key_b in rs.iter_redis_keys_scan(rdb, "magnet:*", count=2000):
        if processed >= int(max_per_run or 30):
            break
        processed += 1

        key = key_b.decode("utf-8") if isinstance(key_b, (bytes, bytearray)) else str(key_b)
        if rs.is_deleted(rdb, key):
            continue

        h = rs.decode_hash(rdb.hgetall(key))
        if not h:
            continue

        if _safe_int(h.get("links_count") or 0, 0) > 0:
            continue

        kind, magnet_id = rs.redis_key_id(key)
        if kind != "magnet" or not magnet_id:
            continue

        before = 0
        try:
            before = _safe_int(h.get("links_count") or 0, 0)
        except Exception:
            before = 0

        _refresh_one_magnet_from_alldebrid(s, rdb, key, magnet_id)

        after = _safe_int((rdb.hget(key, "links_count") or b"0").decode("utf-8", "ignore"), 0)
        if before <= 0 and after > 0:
            updated += 1

    return updated


def _maybe_unlock_urls(s, urls: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()

    for u in (urls or []):
        u = (u or "").strip()
        if not u:
            continue

        # déjà un lien direct final (debrid.it)
        if "debrid.it/dl/" in u:
            if u not in seen:
                seen.add(u); out.append(u)
            continue

        # lien AllDebrid /f/ -> unlock vers debrid.it/dl/
        if "alldebrid.com/f/" in u:
            ok, data_or_err = unlock_link_safe(s, u)
            if ok and isinstance(data_or_err, dict):
                final = (data_or_err.get("link") or "").strip()
                if final:
                    u = final

        if u not in seen:
            seen.add(u); out.append(u)

    return out

def _maybe_send_to_nas(s, rdb: redis.Redis, key: str, data: dict) -> None:
    if not s.nas_enabled:
        return

    if (data.get("app_status") or "").strip() != rs.APP_STATUS_NAS_PENDING:
        return

    links = rs.parse_links_dicts(data)
    urls = [x.get("link") for x in links if isinstance(x, dict) and (x.get("link") or "").strip()]

    if not urls:
        logger.info("[NAS] %s nas_pending mais pas de liens (links_count=%s)", key, data.get("links_count"))
        return

    # lock par clé complète (DOIT être avant les appels réseau)
    if not rs.acquire_nas_send_lock(rdb, lock_id=key, ttl_seconds=900):
        return

    try:
        # unlock JIT
        urls = _maybe_unlock_urls(s, urls)

        # sécurité: n'envoyer QUE des liens finals
        urls = [u for u in urls if u and "debrid.it/dl/" in u]

        if not urls:
            rdb.hset(
                key,
                mapping={
                    "app_status": rs.APP_STATUS_NAS_FAILED,
                    "sent_to_nas": "false",
                    "nas_error": "AD_UNLOCK_FAILED: no final debrid.it links",
                    "nas_last_attempt": str(time.time()),
                },
            )
            logger.warning("[NAS] %s unlock failed: no final links", key)
            return

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
            logger.info("[NAS] sent OK %s (%d links)", key, len(urls))
        else:
            code = (err or {}).get("code") or "NAS_SEND_FAILED"
            msg = (err or {}).get("message") or "send_failed"
            rdb.hset(
                key,
                mapping={
                    "app_status": rs.APP_STATUS_NAS_FAILED,
                    "sent_to_nas": "false",
                    "nas_error": f"{code}: {msg}",
                    "nas_last_attempt": str(time.time()),
                },
            )
            logger.warning("[NAS] failed %s: %s", key, err)

    finally:
        rs.release_nas_send_lock(rdb, lock_id=key)


def check_pending_torrents(s, rdb: redis.Redis) -> None:
    """
    Tick scheduler:
      1) refresh magnets sans liens via AllDebrid (pour alimenter UI)
      2) envoi NAS pour items nas_pending (magnets et directs)
    """
    # 1) refresh magnets: limite par tick pour éviter rate-limit
    try:
        updated = refresh_pending_magnets(s, rdb, max_per_run=int(getattr(s, "scheduler_refresh_max_per_run", 30) or 30))
        if updated:
            logger.info("[REFRESH] magnets updated with links: %d", updated)
    except Exception as e:
        logger.warning("[REFRESH] error: %s", str(e), exc_info=True)

    # 2) NAS send
    keys = rs.iter_all_items_keys(rdb)

    for key_b in keys:
        key = key_b.decode("utf-8") if isinstance(key_b, (bytes, bytearray)) else str(key_b)
        if rs.is_deleted(rdb, key):
            continue

        data = rs.decode_hash(rdb.hgetall(key))
        if not data:
            continue

        _maybe_send_to_nas(s, rdb, key, data)