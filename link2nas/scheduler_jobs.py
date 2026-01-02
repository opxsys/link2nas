# link2nas/scheduler_jobs.py
from __future__ import annotations

import json
import logging
import time
from typing import Any

import redis

from . import redis_store as rs
from .alldebrid import get_magnet_files_safe, get_magnet_status_safe
from .nas_send import send_item_to_nas_safe

logger = logging.getLogger("link2nas.scheduler")

# ==============================================================================
# Scheduler jobs
#
# - Rafraîchit les magnets "en attente de liens" via AllDebrid
# - Déclenche l'envoi NAS pour les items en app_status=nas_pending
#
# Conventions logs
#   - Tous les logs NAS => préfixe [NAS]
#   - Tous les logs refresh AD => préfixe [REFRESH]
#   - Tous les logs loop/scheduler => préfixe [SCHED]
# ==============================================================================


# ==============================================================================
# Small safe helpers (no side effects)
# ==============================================================================
def _b2s(v: Any) -> str:
    """bytes|str|None -> str"""
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", "ignore")
    return str(v)


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


def _now() -> str:
    return str(time.time())


# ==============================================================================
# AllDebrid payload normalization (magnet/files -> links[])
# ==============================================================================
def _flatten_ad_magnet_files(files: list[dict]) -> tuple[list[dict], int]:
    """
    AllDebrid magnet/files peut renvoyer:
      - liste plate: [{n,s,l}, ...]
      - OU liste de dossiers: [{n, e:[{n,s,l}, ...]}, ...]
    On aplati en links[] (format interne redis_store).
    Retourne (links, total_size).
    """
    links: list[dict] = []
    total_size = 0

    def push_file(f: dict) -> None:
        nonlocal total_size
        if not isinstance(f, dict):
            return

        link = str(f.get("l") or f.get("link") or "").strip()
        if not link:
            return

        name = str(f.get("n") or f.get("name") or "").strip() or "file"
        size = _safe_int(f.get("s") or f.get("size") or 0, 0)

        links.append({"name": name, "size": size, "path": name, "link": link})
        total_size += size

    for item in files or []:
        if not isinstance(item, dict):
            continue

        entries = item.get("e")
        if isinstance(entries, list):
            for f in entries:
                push_file(f)
            continue

        push_file(item)

    return links, total_size


# ==============================================================================
# Magnet refresh (AllDebrid -> Redis)
# ==============================================================================
def _has_links(rdb: redis.Redis, redis_key: str) -> bool:
    """True si links_count > 0."""
    try:
        v = _b2s(rdb.hget(redis_key, "links_count") or b"0").strip()
        return _safe_int(v, 0) > 0
    except Exception:
        return False


def _refresh_one_magnet(s, rdb: redis.Redis, redis_key: str, magnet_id: str) -> None:
    """
    Rafraîchit status/progress/links d'un magnet côté Redis.

    Règle app: on considère "terminé" dès que links_count > 0.
    Si on a déjà des liens, on ne retouche pas (évite d'écraser un état final).
    """
    if _has_links(rdb, redis_key):
        return

    # ---- 1) magnet/status (best-effort) ----
    try:
        ok_st, st_or_err = get_magnet_status_safe(s, magnet_id)
        if ok_st and isinstance(st_or_err, dict):
            st = st_or_err
            mapping: dict[str, str] = {}

            ad_status = str(st.get("status") or "").strip().lower()
            if ad_status:
                mapping["status"] = ad_status

            if st.get("progress") is not None:
                mapping["progress"] = str(_safe_float(st.get("progress"), 0.0))
                mapping["unlock_progress"] = mapping["progress"]

            if st.get("size") is not None:
                mapping["size"] = str(_safe_int(st.get("size"), 0))

            if st.get("downloaded") is not None:
                mapping["downloaded"] = str(_safe_int(st.get("downloaded"), 0))

            if mapping:
                rdb.hset(redis_key, mapping=mapping)
    except Exception:
        logger.debug("[REFRESH] magnet/status failed key=%s", redis_key, exc_info=True)

    # ---- 2) magnet/files (source de vérité pour links) ----
    ok_files, files_or_err = get_magnet_files_safe(s, magnet_id)
    if not ok_files:
        err = files_or_err or {}
        code = (err.get("code") or "AD_MAGNET_FILES_FAILED") if isinstance(err, dict) else "AD_MAGNET_FILES_FAILED"
        msg = (err.get("message") or "magnet/files failed") if isinstance(err, dict) else "magnet/files failed"
        rdb.hset(
            redis_key,
            mapping={
                "nas_error": f"{code}: {msg}",
                "nas_last_attempt": _now(),
            },
        )
        return

    files = files_or_err if isinstance(files_or_err, list) else []
    links, total_size = _flatten_ad_magnet_files(files)

    base_mapping: dict[str, str] = {
        "links_raw": json.dumps(files or []),
        "nas_last_attempt": _now(),
    }

    if links:
        base_mapping.update(
            {
                "links": json.dumps(links),
                "links_count": str(len(links)),
                "links_total": str(len(links)),
                "size": str(int(total_size)),
                "downloaded": str(int(total_size)),
                "unlock_progress": "100",
                "progress": "100",
                "status": "completed",
                "nas_error": "",
            }
        )
    else:
        # Pas de liens => on garde le status existant si présent, sinon "pending"
        current_status = _b2s(rdb.hget(redis_key, "status") or b"").strip().lower() or "pending"
        base_mapping.update(
            {
                "links": "[]",
                "links_count": "0",
                "links_total": "0",
                "unlock_progress": "0",
                "status": current_status,
            }
        )

    rdb.hset(redis_key, mapping=base_mapping)


def refresh_pending_magnets(s, rdb: redis.Redis, max_per_run: int = 30) -> int:
    """
    Parcourt magnet:* et rafraîchit ceux qui n'ont pas encore de liens (links_count=0).
    Retourne le nombre de magnets qui viennent de passer à links_count>0.
    """
    updated = 0
    processed = 0
    limit = int(max_per_run or 30)

    for key_b in rs.iter_redis_keys_scan(rdb, "magnet:*", count=2000):
        if processed >= limit:
            break
        processed += 1

        redis_key = _b2s(key_b)
        if rs.is_deleted(rdb, redis_key):
            continue

        h = rs.decode_hash(rdb.hgetall(redis_key))
        if not h:
            continue

        if _safe_int(h.get("links_count") or 0, 0) > 0:
            continue

        kind, magnet_id = rs.redis_key_id(redis_key)
        if kind != "magnet" or not magnet_id:
            continue

        before = _safe_int(h.get("links_count") or 0, 0)
        _refresh_one_magnet(s, rdb, redis_key, magnet_id)
        after = _safe_int(_b2s(rdb.hget(redis_key, "links_count") or b"0"), 0)

        if before <= 0 and after > 0:
            updated += 1

    return updated


# ==============================================================================
# NAS send loop (redis -> nas_send)
# ==============================================================================
def _should_send_to_nas(s, item: dict[str, str]) -> bool:
    """Condition d'entrée: NAS activé et app_status=nas_pending."""
    if not getattr(s, "nas_enabled", False):
        return False
    return (item.get("app_status") or "").strip() == rs.APP_STATUS_NAS_PENDING


def _send_one_to_nas(s, rdb: redis.Redis, redis_key: str, item: dict[str, str]) -> None:
    """
    Envoi NAS "safe":
      - lock Redis avant réseau
      - met à jour app_status + champs NAS
      - logs préfixés [NAS]
    """
    if not _should_send_to_nas(s, item):
        return

    # Lock par clé complète (doit être avant les appels réseau)
    if not rs.acquire_nas_send_lock(rdb, lock_id=redis_key, ttl_seconds=900):
        return

    try:
        ok, err = send_item_to_nas_safe(s, rdb, redis_key)
        if ok:
            rdb.hset(
                redis_key,
                mapping={
                    "app_status": rs.APP_STATUS_NAS_SENT,
                    "sent_to_nas": "true",
                    "sent_to_nas_at": _now(),
                    "nas_error": "",
                    "nas_last_attempt": _now(),
                },
            )
            logger.info("[NAS] sent OK key=%s", redis_key)
            return

        # err attendu: dict {code,message} (mais on tolère str)
        if isinstance(err, dict):
            code = err.get("code") or "NAS_SEND_FAILED"
            msg = err.get("message") or "send_failed"
            err_txt = f"{code}: {msg}"
        else:
            err_txt = str(err or "send_failed")

        rdb.hset(
            redis_key,
            mapping={
                "app_status": rs.APP_STATUS_NAS_FAILED,
                "sent_to_nas": "false",
                "nas_error": err_txt,
                "nas_last_attempt": _now(),
            },
        )
        logger.warning("[NAS] failed key=%s err=%s", redis_key, err_txt)

    finally:
        rs.release_nas_send_lock(rdb, lock_id=redis_key)


# ==============================================================================
# Scheduler entrypoint (imported by scheduler_runner.py)
# ==============================================================================
def check_pending_torrents(s, rdb: redis.Redis) -> None:
    """
    Tick scheduler:
      1) Refresh magnets sans liens via AllDebrid (alimente UI)
      2) Envoi NAS pour items en nas_pending (magnets et directs)
    """
    # 1) Refresh magnets (capé)
    try:
        max_per_run = int(getattr(s, "max_unlock_per_run", 30) or 30)
        updated = refresh_pending_magnets(s, rdb, max_per_run=max_per_run)
        if updated:
            logger.info("[REFRESH] magnets updated with links=%d", updated)
    except Exception:
        logger.warning("[REFRESH] error", exc_info=True)

    # 2) NAS send loop (tous items)
    try:
        for key_b in rs.iter_all_items_keys(rdb):
            redis_key = _b2s(key_b)
            if rs.is_deleted(rdb, redis_key):
                continue

            item = rs.decode_hash(rdb.hgetall(redis_key))
            if not item:
                continue

            _send_one_to_nas(s, rdb, redis_key, item)

    except Exception:
        logger.warning("[SCHED] loop error", exc_info=True)
