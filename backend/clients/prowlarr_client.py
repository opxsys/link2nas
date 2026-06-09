import logging

import requests

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 10   # seconds
_READ_TIMEOUT = 30      # seconds
_SEARCH_READ_TIMEOUT = 60


class ProwlarrClientError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _normalize_base_url(raw: str) -> str:
    url = str(raw or "").strip().rstrip("/")
    if not url:
        raise ValueError("Prowlarr base_url is empty")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(f"Prowlarr base_url must start with http:// or https://, got: {url!r}")
    return url


class ProwlarrClient:
    def __init__(self, base_url: str, api_key: str):
        self._base = _normalize_base_url(base_url)
        self._api_key = api_key

    # ── internal ────────────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None, *, read_timeout: int = _READ_TIMEOUT) -> object:
        url = f"{self._base}{path}"
        try:
            resp = requests.get(
                url,
                params=params,
                headers={"X-Api-Key": self._api_key},
                timeout=(_CONNECT_TIMEOUT, read_timeout),
            )
            resp.raise_for_status()
            return resp.json()
        except requests.Timeout as exc:
            raise ProwlarrClientError("PROWLARR_CONNECTION_FAILED", "Connection timed out") from exc
        except requests.ConnectionError as exc:
            raise ProwlarrClientError("PROWLARR_CONNECTION_FAILED", "Unable to connect to Prowlarr") from exc
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            raise ProwlarrClientError("PROWLARR_CONNECTION_FAILED", f"Prowlarr returned HTTP {code}") from exc
        except ProwlarrClientError:
            raise
        except Exception as exc:
            raise ProwlarrClientError("PROWLARR_CONNECTION_FAILED", "Unexpected error contacting Prowlarr") from exc

    # ── public API ──────────────────────────────────────────────────────────────

    def test_connection(self) -> dict:
        """Returns {version, active_indexers}. Raises ProwlarrClientError on failure."""
        status = self._get("/api/v1/system/status")
        version = status.get("version", "unknown") if isinstance(status, dict) else "unknown"

        active_indexers = 0
        try:
            indexers = self._get("/api/v1/indexer")
            if isinstance(indexers, list):
                active_indexers = sum(1 for i in indexers if i.get("enable", False))
        except ProwlarrClientError:
            pass  # best-effort — status already confirmed

        logger.info("Prowlarr connection test succeeded (version=%s indexers=%d)", version, active_indexers)
        return {"version": version, "active_indexers": active_indexers}

    def get_indexers(self) -> list[dict]:
        """Returns simplified list of enabled indexers."""
        raw = self._get("/api/v1/indexer")
        if not isinstance(raw, list):
            return []

        return [
            {
                "id": i.get("id"),
                "name": i.get("name", ""),
                "enabled": True,
                "protocol": (i.get("protocol") or "").lower(),
            }
            for i in raw
            if i.get("enable", False)
        ]

    def search(
        self,
        query: str,
        *,
        categories: list[int] | None = None,
        indexer_ids: list[int] | None = None,
        limit: int = 50,
        min_seeders: int | None = None,
    ) -> list[dict]:
        params: dict = {"Query": query, "Limit": min(limit, 100)}
        if categories:
            params["Categories[]"] = [str(c) for c in categories]
        if indexer_ids:
            params["IndexerIds[]"] = [str(i) for i in indexer_ids]

        try:
            raw = self._get("/api/v1/search", params, read_timeout=_SEARCH_READ_TIMEOUT)
        except ProwlarrClientError as exc:
            raise ProwlarrClientError("PROWLARR_SEARCH_FAILED", exc.message) from exc

        if not isinstance(raw, list):
            return []

        results = []
        for item in raw:
            seeders = int(item.get("seeders") or 0)
            if min_seeders is not None and seeders < min_seeders:
                continue

            cats = []
            for cat in (item.get("categories") or []):
                if isinstance(cat, dict):
                    name = cat.get("name", "")
                    if name:
                        cats.append(name)
                elif isinstance(cat, str) and cat:
                    cats.append(cat)

            # magnet_url is safe to expose (no API key).
            # download_url routes through Prowlarr and may carry sensitive tokens;
            # Bloc 4 (create-job) will resolve it server-side — never log it.
            results.append({
                "guid": item.get("guid") or item.get("title", ""),
                "title": item.get("title", ""),
                "indexer": item.get("indexer", ""),
                "indexer_id": item.get("indexerId"),
                "size": item.get("size"),
                "seeders": seeders,
                "leechers": int(item.get("leechers") or 0),
                "publish_date": item.get("publishDate"),
                "categories": cats,
                "magnet_url": item.get("magnetUrl") or None,
                "download_url": item.get("downloadUrl") or None,
                "info_url": item.get("infoUrl") or None,
            })

        logger.info("Prowlarr search returned %d results", len(results))
        return results
