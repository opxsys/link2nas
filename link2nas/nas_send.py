# link2nas/nas_send.py
from __future__ import annotations

import hashlib
import logging
import os
import re
import time
import unicodedata
from typing import Any, Tuple
from urllib.parse import urlparse

import redis

from .alldebrid import unlock_link_safe
from .config import Settings
from .redis_store import get_nas_folder, parse_links_dicts, set_nas_folder
from .synology_fs import (
    dsm_get_api_info,
    dsm_login,
    dsm_logout,
    downloadstation_task_create,
    filestation_mkdir,
    SynologyApiError,
)

logger = logging.getLogger("link2nas.nas_send")


def _ascii(s: str) -> str:
    s = (s or "").strip()
    s = unicodedata.normalize("NFKD", s)
    return s.encode("ascii", "ignore").decode("ascii", "ignore")


def _extract_date_token(s: str) -> str:
    s = (s or "")
    m = re.search(r"[\[\［](\d{4})[.\-\/](\d{2})[.\-\/](\d{2})[\]\］]", s)
    if not m:
        m = re.search(r"(\d{4})[.\-\/](\d{2})[.\-\/](\d{2})", s)
    if not m:
        return ""
    return f"{m.group(1)}{m.group(2)}{m.group(3)}"


def _slug(s: str, max_words: int = 10) -> str:
    """
    Slug ASCII lisible, privilégie les tokens contenant des lettres.
    Retourne "item" si rien d'exploitable.
    """
    s_ascii = _ascii(s)
    s_ascii = re.sub(r"[\[\［][^\]\］]*[\]\］]", " ", s_ascii)
    s_ascii = re.sub(r"\([^)]*\)", " ", s_ascii)
    s_ascii = re.sub(r"[\"'`]", " ", s_ascii)
    s_ascii = re.sub(r"&", " and ", s_ascii)
    s_ascii = re.sub(r"[^a-zA-Z0-9\s._-]+", " ", s_ascii)

    tokens = [t for t in re.split(r"[\s._-]+", s_ascii) if t]
    if not tokens:
        return "item"

    alpha = [t for t in tokens if re.search(r"[A-Za-z]", t)]
    use = (alpha or tokens)[:max_words]

    out = "-".join(use).lower()
    out = re.sub(r"-{2,}", "-", out).strip("-")

    if not re.search(r"[a-z]", out):
        return "item"
    return out or "item"


def _redact_url(u: str) -> str:
    s = str(u or "").strip()
    if not s:
        return ""
    host = ""
    try:
        host = (urlparse(s).netloc or "").lower().replace("www.", "")
    except Exception:
        host = ""
    h = hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{host}#{h}"


def _redact_list(urls: list[str], limit: int = 5) -> list[str]:
    out = []
    for u in (urls or [])[:limit]:
        out.append(_redact_url(u))
    if urls and len(urls) > limit:
        out.append(f"...(+{len(urls)-limit})")
    return out


def _make_folder_name(base: str, max_len: int = 64) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    base = (base or "").strip()

    if re.search(r"\.[A-Za-z0-9]{2,5}$", base):
        base = os.path.splitext(base)[0]

    date_token = _extract_date_token(base)
    core = _slug(base, max_words=10)

    parts = [core]
    if date_token:
        parts.append(date_token)
    parts.append(ts)

    name = "-".join(parts)
    name = name[:max_len].rstrip(".-_")
    return name or f"item-{ts}"


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(str(x).strip())
    except Exception:
        return default


def _maybe_unlock_urls(s: Settings, urls: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()

    for u in urls or []:
        u = (u or "").strip()
        if not u:
            continue

        if "debrid.it/dl/" in u:
            if u not in seen:
                seen.add(u)
                out.append(u)
            continue

        if "alldebrid.com/f/" in u:
            ok, data_or_err = unlock_link_safe(s, u)
            if ok and isinstance(data_or_err, dict):
                final = (data_or_err.get("link") or "").strip()
                if final:
                    u = final

        if u and u not in seen:
            seen.add(u)
            out.append(u)

    return out


def _pick_base_name(decoded: dict, links: list[dict], redis_key: str) -> str:

    title = (decoded.get("name") or "").strip()
    domain = (decoded.get("source_domain") or "").strip()

    if domain and title:
        return f"{domain} {title}".strip()
    if title:
        return title

    if links and isinstance(links[0], dict):
        ln = (links[0].get("name") or "").strip()
        if ln:
            return ln

    return redis_key.split(":", 1)[-1]


def send_item_to_nas_safe(s: Settings, rdb: redis.Redis, redis_key: str) -> Tuple[bool, dict | None]:
    """
    Envoie les liens d’un item Redis vers Synology Download Station.
    Gère le mode dossier (multi-liens / batch) et persiste nas_folder + ds_dest_mode.
    """
    if not s.nas_enabled:
        return False, {"code": "NAS_DISABLED", "message": "NAS disabled by configuration"}

    raw = rdb.hgetall(redis_key)
    if not raw:
        logger.warning("[NAS][REDIS] key=%s not found", redis_key)
        return False, {"code": "NOT_FOUND", "message": f"redis key not found: {redis_key}"}

    decoded = {
        (k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)): (
            v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
        )
        for k, v in raw.items()
    }

    try:
        logger.info(
            "[NAS][ITEM] key=%s type=%s app_status=%s links_count=%r links_total=%r is_batch=%r source_domain=%r nas_folder=%r ds_dest_mode=%r name=%r size=%r status=%r",
            redis_key,
            decoded.get("type"),
            decoded.get("app_status"),
            decoded.get("links_count"),
            decoded.get("links_total"),
            decoded.get("is_batch"),
            decoded.get("source_domain"),
            decoded.get("nas_folder"),
            decoded.get("ds_dest_mode"),
            decoded.get("name"),
            decoded.get("size"),
            decoded.get("status"),
        )
    except Exception:
        pass

    links = parse_links_dicts(decoded)
    links_count = _safe_int(decoded.get("links_count") or 0, 0)

    if links_count <= 0 or not links:
        logger.warning(
            "[NAS][NO_LINKS] key=%s links_count(redis)=%r parsed_links=%r",
            redis_key,
            decoded.get("links_count"),
            (len(links) if links else 0),
        )
        return False, {"code": "NO_LINKS", "message": "no links to send"}

    urls_raw = [(d.get("link") or "").strip() for d in links if isinstance(d, dict)]
    urls_raw = [u for u in urls_raw if u]
    if not urls_raw:
        logger.warning("[NAS][NO_URLS] key=%s parsed_links=%d but no .link field", redis_key, len(links))
        return False, {"code": "NO_LINKS", "message": "no links to send"}

    logger.info("[NAS][URLS_RAW] key=%s urls_from_redis=%d first=%s", redis_key, len(urls_raw), _redact_url(urls_raw[0]))

    urls_before = list(urls_raw)
    urls_unlocked = _maybe_unlock_urls(s, urls_raw)

    try:
        logger.info(
            "[NAS][UNLOCK] key=%s urls_before=%d urls_after_unlock=%d changed=%s",
            redis_key,
            len(urls_before),
            len(urls_unlocked),
            "yes" if urls_unlocked != urls_before else "no",
        )
        logger.debug("[NAS][UNLOCK] key=%s urls_before_sample=%s", redis_key, _redact_list(urls_before))
        logger.debug("[NAS][UNLOCK] key=%s urls_after_unlock_sample=%s", redis_key, _redact_list(urls_unlocked))
    except Exception:
        pass

    urls_final = [u for u in urls_unlocked if "debrid.it/dl/" in (u or "")]
    urls_final = [u for u in urls_final if u]
    if not urls_final:
        logger.error(
            "[NAS][AD_UNLOCK_FAILED] key=%s no final debrid.it links after unlock. urls_after_unlock_sample=%s",
            redis_key,
            _redact_list(urls_unlocked),
        )
        return False, {"code": "AD_UNLOCK_FAILED", "message": "no final debrid.it links after unlock"}

    logger.info("[NAS][URLS_FINAL] key=%s urls_final=%d sample=%s", redis_key, len(urls_final), _redact_url(urls_final[0]))

    is_batch_flag = str(decoded.get("is_batch") or "").strip() == "1"
    make_folder = (len(urls_final) > 1) or is_batch_flag

    folder_redis = (get_nas_folder(rdb, redis_key) or "").strip()
    base_name = _pick_base_name(decoded, links, redis_key)

    logger.info(
        "[NAS][DECISION] key=%s make_folder=%s reason=(urls_final=%d is_batch=%r source_domain=%r links_count=%r) folder_redis=%r base_name=%r",
        redis_key,
        make_folder,
        len(urls_final),
        decoded.get("is_batch"),
        decoded.get("source_domain"),
        decoded.get("links_count"),
        folder_redis,
        base_name,
    )

    api_info = dsm_get_api_info(s)
    sess = dsm_login(s, api_info)

    try:
        filestation_base = str(getattr(s, "filestation_base_path", "") or "").strip().rstrip("/") or "/downloads"
        destination_root = str(getattr(s, "dsm_destination_base", "") or "").strip().strip() or "downloads"

        if not destination_root.startswith("/"):
            destination_root = "/" + destination_root

        logger.info("[NAS][DSM] key=%s filestation_base=%r destination_root=%r", redis_key, filestation_base, destination_root)

        def _try_enqueue(dest: str) -> tuple[bool, dict | None]:
            created = 0
            try:
                logger.info("[NAS][DS][TRY] key=%s destination=%r urls=%d", redis_key, dest, len(urls_final))

                for i, u in enumerate(urls_final, start=1):
                    logger.info(
                        "[NAS][DS][CREATE] key=%s %d/%d destination=%r uri=%s",
                        redis_key, i, len(urls_final), dest, _redact_url(u)
                    )
                    downloadstation_task_create(s, api_info, sess, uri=u, destination=dest)
                    created += 1
                return True, None

            except SynologyApiError as e:
                is_403 = (e.code == 403)
                if is_403:
                    logger.info("[NAS][DS][DEST_REJECTED] key=%s destination=%r code=403 created=%d", redis_key, dest, created)
                else:
                    logger.warning("[NAS][DS][CREATE_FAILED] key=%s destination=%r code=%r http=%r created=%d", redis_key, dest, e.code, e.http_status, created)
                    logger.warning("[NAS][DS][CREATE_FAILED] %s", e.to_dict())

                # IMPORTANT: si on a déjà créé au moins une tâche, on NE fallback PAS (risque doublons)
                return False, {
                    "code": "DS_CREATE_FAILED",
                    "message": str(e),
                    "dest": dest,
                    "is_403": is_403,
                    "partial_created": created,
                    "stop_fallback": (created > 0),
                }

            except Exception as e:
                logger.exception("[NAS][DS][EXC] key=%s destination=%r unexpected exception created=%d", redis_key, dest, created)
                return False, {
                    "code": "DS_CREATE_FAILED",
                    "message": repr(e),
                    "dest": dest,
                    "is_403": False,
                    "partial_created": created,
                    "stop_fallback": (created > 0),
                }

        if not make_folder:
            logger.info("[NAS][ENQUEUE] key=%s MODE=root destination=%r urls=%d", redis_key, destination_root, len(urls_final))
            ok, err = _try_enqueue(destination_root)
            return (True, None) if ok else (False, err)

        folder = folder_redis
        if not folder:
            folder = _make_folder_name(base_name, max_len=64)
            if folder.startswith("item-") and links and isinstance(links[0], dict):
                alt = (links[0].get("name") or "").strip()
                if alt:
                    alt_folder = _make_folder_name(alt, max_len=64)
                    if not alt_folder.startswith("item-"):
                        folder = alt_folder

            logger.info("[NAS][MKDIR] key=%s parent=%r folder=%r", redis_key, filestation_base, folder)
            filestation_mkdir(s, api_info, sess, parent_path=filestation_base, name=folder)
            set_nas_folder(rdb, redis_key, folder)
            logger.info("[NAS][MKDIR] key=%s mkdir OK folder=%r (persisted)", redis_key, folder)

        ds_mode = str(decoded.get("ds_dest_mode") or "").strip().lower()
        dest_folder = folder
        dest_rel = f"{destination_root}/{folder}".strip("/")
        dest_fs = f"{filestation_base}/{folder}".replace("//", "/")

        order: list[str] = []
        if ds_mode in {"rel", "fs", "folder"}:
            order.append(ds_mode)

        # ordre par défaut: rel -> fs -> folder
        for m in ("rel", "fs", "folder"):
            if m not in order:
                order.append(m)

        candidates = {"folder": dest_folder, "rel": dest_rel, "fs": dest_fs}

        logger.info("[NAS][ENQUEUE] key=%s MODE=folder folder=%r order=%s", redis_key, folder, order)

        last_err = None
        for mode in order:
            dest = candidates[mode]
            logger.info("[NAS][DS] key=%s try mode=%s dest=%r", redis_key, mode, dest)

            ok, err = _try_enqueue(dest)
            if ok:
                try:
                    rdb.hset(redis_key, mapping={"ds_dest_mode": mode})
                except Exception as e:
                    logger.warning("[NAS][DS] key=%s failed to persist ds_dest_mode=%s err=%r", redis_key, mode, e)
                logger.info("[NAS] enqueue OK key=%s mode=%s dest=%r folder=%r urls=%d", redis_key, mode, dest, folder, len(urls_final))
                return True, None

            last_err = err
            if err and err.get("is_403"):
                continue
            return False, err

        logger.error("[NAS] enqueue failed after all modes key=%s last_err=%s", redis_key, last_err)
        return False, last_err or {"code": "DS_CREATE_FAILED", "message": "unknown DS failure"}

    finally:
        try:
            dsm_logout(s, api_info, sess)
        except Exception:
            logger.exception("[NAS][DSM] key=%s logout failed", redis_key)
