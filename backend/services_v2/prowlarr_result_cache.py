import re
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

_HTTP_RE = re.compile(r"^https?://", re.IGNORECASE)


def _extract_real_magnet(raw_item: dict) -> str | None:
    """Return the first genuine magnet:? URI found across magnetUrl, downloadUrl, then guid.

    Never logs or returns partial values — caller gets the full URI or None.
    """
    for key in ("magnet_url", "download_url", "guid"):
        v = (raw_item.get(key) or "").strip()
        if v.startswith("magnet:?"):
            return v
    return None


def _extract_real_torrent_url(raw_item: dict) -> str | None:
    """Return download_url only when it's a genuine HTTP(S) URL.

    If download_url is a magnet URI it is already handled by _extract_real_magnet;
    returning it here as a torrent fetch target would be wrong.
    """
    v = (raw_item.get("download_url") or "").strip()
    return v if _HTTP_RE.match(v) else None


_DEFAULT_TTL_MINUTES = 20


@dataclass
class CachedProwlarrResult:
    result_id: str
    user_id: str            # for isolation check at job-creation time (Bloc 4)
    title: str
    download_url: str | None
    magnet_url: str | None
    info_url: str | None
    indexer: str
    indexer_id: int | None
    expires_at: datetime
    # Resolved fields — never exposed to clients
    real_magnet_url: str | None   # first real magnet:? URI across magnet_url/download_url/guid
    real_torrent_url: str | None  # download_url only when HTTP(S), safe for server-side fetch


class ProwlarrResultCache:
    """
    Short-lived in-memory cache for Prowlarr search results.

    Sensitive URLs (download_url, magnet_url, info_url) are stored server-side
    and never returned to clients. Clients receive an opaque result_id;
    job creation (Bloc 4) resolves it via get_for_user().

    Thread-safe. Eviction runs opportunistically on each store_results() call.
    """

    def __init__(self, ttl_minutes: int = _DEFAULT_TTL_MINUTES):
        self._ttl = timedelta(minutes=ttl_minutes)
        self._lock = threading.Lock()
        self._entries: dict[str, CachedProwlarrResult] = {}

    def store_results(self, raw_results: list[dict], user_id: str) -> list[dict]:
        """
        Stores sensitive fields server-side; returns public-safe list.

        download_url, magnet_url, and info_url are all stored server-side only.
        The returned dicts carry boolean flags (has_download, has_magnet,
        has_info_url) so the UI can show appropriate action buttons.
        """
        now = datetime.now(UTC)
        expires = now + self._ttl
        safe: list[dict] = []

        with self._lock:
            self._evict(now)
            for item in raw_results:
                rid = str(uuid.uuid4())
                real_magnet = _extract_real_magnet(item)
                real_torrent = _extract_real_torrent_url(item)
                self._entries[rid] = CachedProwlarrResult(
                    result_id=rid,
                    user_id=user_id,
                    title=item.get("title", ""),
                    download_url=item.get("download_url"),
                    magnet_url=item.get("magnet_url"),
                    info_url=item.get("info_url"),
                    indexer=item.get("indexer", ""),
                    indexer_id=item.get("indexer_id"),
                    expires_at=expires,
                    real_magnet_url=real_magnet,
                    real_torrent_url=real_torrent,
                )
                safe.append({
                    "result_id": rid,
                    "title": item.get("title", ""),
                    "indexer": item.get("indexer", ""),
                    "indexer_id": item.get("indexer_id"),
                    "size": item.get("size"),
                    "seeders": item.get("seeders", 0),
                    "leechers": item.get("leechers", 0),
                    "publish_date": item.get("publish_date"),
                    "categories": item.get("categories", []),
                    "has_download": bool(item.get("download_url")),
                    "has_magnet": bool(item.get("magnet_url")),
                    "has_info_url": bool(item.get("info_url")),
                    "has_real_magnet": bool(real_magnet),
                    "has_torrent_download": bool(real_torrent),
                })

        return safe

    def get(self, result_id: str) -> CachedProwlarrResult | None:
        """Returns cached entry, or None if missing or expired."""
        now = datetime.now(UTC)
        with self._lock:
            entry = self._entries.get(result_id)
            if entry is None:
                return None
            if entry.expires_at <= now:
                del self._entries[result_id]
                return None
            return entry

    def get_for_user(self, result_id: str, user_id: str) -> CachedProwlarrResult | None:
        """Returns cached entry only if it belongs to the given user."""
        entry = self.get(result_id)
        if entry is None:
            return None
        if entry.user_id != user_id:
            return None
        return entry

    def _evict(self, now: datetime) -> None:
        expired = [k for k, v in self._entries.items() if v.expires_at <= now]
        for k in expired:
            del self._entries[k]
