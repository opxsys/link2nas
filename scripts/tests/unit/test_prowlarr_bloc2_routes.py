#!/usr/bin/env python3
"""
Unit tests: Prowlarr Bloc 2 routes.

Covers:
  Admin routes (/api/v2/admin/prowlarr):
    1.  GET / — no config → empty state
    2.  GET / — with config → safe dict, no api_key exposed
    3.  GET / — non-admin → 403
    4.  GET / — no auth → 401
    5.  PATCH / — valid save → updated safe dict
    6.  PATCH / — enabled without base_url → 400
    7.  PATCH / — non-admin → 403
    8.  POST /test — success → {ok: true, version, active_indexers}
    9.  POST /test — connection failure → {ok: false, message}
    10. POST /test — not configured → 400 PROWLARR_NOT_CONFIGURED

  Me routes (/api/v2/me/prowlarr):
    11. GET / — no config at all → source=none, search_available=false
    12. GET / — global config exists → source=global, search_available=true
    13. GET / — own user config → source=user, search_available=true, user_config present
    14. PATCH / — valid update → safe dict returned
    15. PATCH / — enabled without base_url → 400
    16. POST /test — user config → {ok: true, source: "user"}
    17. POST /test — global fallback → {ok: true, source: "global"}
    18. POST /test — not configured → 400 PROWLARR_NOT_CONFIGURED
    19. POST /test — connection failure → {ok: false}

  Search routes (/api/v2/prowlarr):
    20. GET /status — configured → {available: true, source, version}
    21. GET /status — not configured → {available: false, source: "none"}
    22. GET /status — configured but connection fails → {available: false}
    23. GET /indexers — configured → list of indexers
    24. GET /indexers — not configured → 400 PROWLARR_NOT_CONFIGURED
    25. GET /indexers — client error → 502
    26. POST /search — valid query → {source, results, total_filtered, has_next}
    27. POST /search — not configured → 400 PROWLARR_NOT_CONFIGURED
    28. POST /search — client error → 502 PROWLARR_SEARCH_FAILED
    29. POST /search — empty query + period=week → 200
    29b. POST /search — empty query + period=all → 400 PROWLARR_EMPTY_QUERY_NO_PERIOD
    29c. POST /search — empty query + period=all + categories → 400 (categories don't bypass rule)

  Pagination (local, not forwarded to Prowlarr):
    37. limit=25, offset=0 → 25 results, has_next=True (60 total)
    38. limit=25, offset=25 → 25 results, has_next=True
    39. limit=25, offset=50 → 10 results, has_next=False
    40. client never receives offset param (pagination is local)

  Period filtering (server-side):
    41. period=today → only today's results
    42. period=week → only last 7 days
    43. period=month → only last 30 days
    44. period=all → no filter (requires non-empty query)

  Filter passthrough for empty-query + period searches:
    45. empty query + period=week + categories=[2000] → client receives categories=[2000]
    46. empty query + period=month + indexer_ids=[1] → client receives indexer_ids=[1]
    47. empty query + period=today + both filters → both forwarded to client
    48. empty query + period=all + categories/indexer_ids → still 400 (client never called)
    49. no filters selected → client receives categories=None, indexer_ids=None (= all)

  HTTP param encoding (ProwlarrClient.search → requests.get):
    50. indexer_ids=[1,2] → two separate indexerIds params in HTTP request
    51. categories=[2000,5000] → two separate categories params in HTTP request
    52. indexer_ids=[1,2] + categories=[2000,5000] → four repeated params total
    53. offset never sent to Prowlarr
    54. wrong param names (Categories[], IndexerIds[], categories, indexer_ids) never sent

  Public source flags (no raw URLs ever exposed):
    30. source_debug absent from results (regression)
    31. has_real_magnet=True when magnet_url is a real magnet:?
    32. has_real_magnet=True when guid is the real magnet:? (not magnet_url)
    33. has_real_magnet=False when magnet_url is an HTTPS redirect
    34. has_torrent_download=True when download_url is HTTP(S)
    35. has_torrent_download=False when download_url is a magnet:? URI
    36. has_real_magnet=False, has_torrent_download=False when all fields empty

Run from project root:
    python3 scripts/tests/unit/test_prowlarr_bloc2_routes.py
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask

from backend.models.prowlarr_config import ProwlarrConfig
from backend.models.user import User
from backend.routes_v2._context import ApiAuthError
from backend.routes_v2.admin_prowlarr import admin_prowlarr_bp
from backend.routes_v2.me_prowlarr import me_prowlarr_bp
from backend.routes_v2.prowlarr_search import prowlarr_search_bp
from backend.services_v2.prowlarr_config_service import ProwlarrConfigService, EffectiveConfig
from backend.services_v2.prowlarr_result_cache import ProwlarrResultCache
from backend.services_v2.crypto_service import CryptoService
from backend.clients.prowlarr_client import ProwlarrClientError
from backend.utils.time import utc_now_iso

# ── Constants ─────────────────────────────────────────────────────────────────

_SUPER_TOKEN = "tok-super"
_USER_TOKEN = "tok-user"
_SUPER_ID = "user-super"
_USER_ID = "user-regular"


# ── Auth fakes ────────────────────────────────────────────────────────────────

class _FakeApiToken:
    def __init__(self, user_id: str):
        self.user_id = user_id


class FakeTokenRepo:
    def get_active_by_token(self, token: str):
        mapping = {_SUPER_TOKEN: _SUPER_ID, _USER_TOKEN: _USER_ID}
        uid = mapping.get(token)
        return _FakeApiToken(uid) if uid else None


class FakeUserRepo:
    def get_by_id(self, uid: str) -> User | None:
        ts = utc_now_iso()
        roles = {_SUPER_ID: "super_admin", _USER_ID: "user"}
        if uid not in roles:
            return None
        return User(
            id=uid,
            email=f"{uid}@example.com",
            display_name=uid,
            role=roles[uid],
            is_active=True,
            created_at=ts,
            updated_at=ts,
        )


class FakeSettings:
    LINK2NAS_SINGLE_USER_MODE = False


# ── Prowlarr client fakes ─────────────────────────────────────────────────────

class FakeProwlarrClientOk:
    def __init__(self, base_url: str, api_key: str):
        pass

    def test_connection(self) -> dict:
        return {"version": "1.28.0", "active_indexers": 5}

    def get_indexers(self) -> list:
        return [{"id": 1, "name": "Test Indexer", "enabled": True, "protocol": "torrent"}]

    def search(self, query, **kw) -> list:
        return [
            {
                "guid": "guid-001",
                "title": "Test Release",
                "indexer": "Test Indexer",
                "indexer_id": 1,
                "size": 1_000_000,
                "seeders": 10,
                "leechers": 2,
                "publish_date": "2026-06-10T00:00:00Z",
                "categories": ["Movies"],
                "magnet_url": "magnet:?xt=urn:btih:abc&tr=https://tracker.example.com/passkey/secret",
                "download_url": "https://prowlarr.example.com/api?token=secret-token",
                "info_url": "https://tracker.example.com/torrent/1234",
            }
        ]


class FakeProwlarrClientFail:
    def __init__(self, base_url: str, api_key: str):
        pass

    def test_connection(self) -> dict:
        raise ProwlarrClientError("PROWLARR_CONNECTION_FAILED", "Connection refused")

    def get_indexers(self) -> list:
        raise ProwlarrClientError("PROWLARR_CONNECTION_FAILED", "Connection refused")

    def search(self, query, **kw) -> list:
        raise ProwlarrClientError("PROWLARR_SEARCH_FAILED", "Search failed")


# Fixed base time for FakeProwlarrClient60 — computed once so all calls
# produce identical dates regardless of when each HTTP request arrives.
_FC60_BASE = datetime.now(timezone.utc)
_FC60_DIST = [
    (5,  timedelta(hours=1)),   # today, week, month
    (10, timedelta(days=3)),    # week, month
    (15, timedelta(days=15)),   # month only
    (30, timedelta(days=40)),   # old (period=all only)
]
_FC60_RESULTS: list = []
_idx = 0
for _count, _delta in _FC60_DIST:
    for _ in range(_count):
        _FC60_RESULTS.append({
            "guid": f"guid-{_idx:03d}",
            "title": f"Release {_idx:03d}",
            "indexer": "Test Indexer",
            "indexer_id": 1,
            "size": 1_000_000,
            "seeders": 0,
            "leechers": 0,
            "publish_date": (_FC60_BASE - _delta).isoformat(),
            "categories": [],
            "magnet_url": None,
            "download_url": f"https://example.com/d/{_idx}",
            "info_url": None,
        })
        _idx += 1
del _count, _delta, _idx  # clean up loop vars from module namespace


class FakeProwlarrClient60:
    """
    Returns 60 results with a controlled publish_date distribution (fixed dates):
      5  results from 1 hour ago   → today, week, month
      10 results from 3 days ago  → week, month
      15 results from 15 days ago → month only
      30 results from 40 days ago → outside month (period=all only)
    Dates are computed once at import time so cross-request comparisons are exact.
    """
    def __init__(self, base_url: str, api_key: str):
        pass

    def test_connection(self) -> dict:
        return {"version": "1.28.0", "active_indexers": 5}

    def get_indexers(self) -> list:
        return [{"id": 1, "name": "Test Indexer", "enabled": True, "protocol": "torrent"}]

    def search(self, query, **kw) -> list:
        return list(_FC60_RESULTS)


# ── Service / repo fakes ──────────────────────────────────────────────────────

class FakeProwlarrConfigRepository:
    def __init__(self):
        self._global: ProwlarrConfig | None = None
        self._users: dict[str, ProwlarrConfig] = {}

    def get_global(self): return self._global
    def get_for_user(self, uid): return self._users.get(uid)
    def upsert(self, cfg):
        if cfg.scope == "global":
            self._global = cfg
        else:
            self._users[cfg.user_id] = cfg
    def delete_global(self): self._global = None
    def delete_for_user(self, uid): self._users.pop(uid, None)


def _make_crypto() -> CryptoService:
    from cryptography.fernet import Fernet
    return CryptoService(Fernet.generate_key().decode())


def _make_svc() -> tuple[ProwlarrConfigService, FakeProwlarrConfigRepository, CryptoService]:
    repo = FakeProwlarrConfigRepository()
    crypto = _make_crypto()
    svc = ProwlarrConfigService(repository=repo, crypto_service=crypto)
    return svc, repo, crypto


# ── App factory ───────────────────────────────────────────────────────────────

def _make_app(svc, client_factory=FakeProwlarrClientOk, cache=None) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SETTINGS"] = FakeSettings()
    app.config["API_TOKEN_REPO_V2"] = FakeTokenRepo()
    app.config["USER_REPO_V2"] = FakeUserRepo()
    app.config["PROWLARR_CONFIG_SERVICE_V2"] = svc
    app.config["PROWLARR_CLIENT_FACTORY"] = client_factory
    app.config["PROWLARR_RESULT_CACHE_V2"] = cache if cache is not None else ProwlarrResultCache(ttl_minutes=5)
    app.register_blueprint(admin_prowlarr_bp)
    app.register_blueprint(me_prowlarr_bp)
    app.register_blueprint(prowlarr_search_bp)

    @app.errorhandler(ApiAuthError)
    def handle_auth(e):
        return {"error": e.message}, 401

    return app


def _auth(token: str = _SUPER_TOKEN) -> dict:
    return {"headers": {"X-Api-Key": token}}


def _json(data: dict) -> dict:
    return {
        "data": json.dumps(data),
        "content_type": "application/json",
    }


# ── Admin routes ──────────────────────────────────────────────────────────────

class TestAdminProwlarrGet(unittest.TestCase):

    def test_no_config_returns_empty_state(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/admin/prowlarr", **_auth())
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["enabled"])
        self.assertFalse(data["has_api_key"])
        self.assertNotIn("api_key", data)
        self.assertNotIn("encrypted_api_key", data)

    def test_with_config_returns_safe_dict(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="secret")
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/admin/prowlarr", **_auth())
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["enabled"])
        self.assertTrue(data["has_api_key"])
        self.assertNotIn("api_key", data)
        self.assertNotIn("encrypted_api_key", data)
        self.assertEqual(data["base_url"], "https://p.example.com")

    def test_non_admin_forbidden(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/admin/prowlarr", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 403)

    def test_no_auth_unauthorized(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/admin/prowlarr")
        self.assertEqual(r.status_code, 401)


class TestAdminProwlarrPatch(unittest.TestCase):

    def test_valid_save_returns_safe_dict(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.patch(
            "/api/v2/admin/prowlarr",
            **_auth(),
            **_json({"enabled": True, "base_url": "https://p.example.com", "api_key": "key"}),
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["has_api_key"])
        self.assertNotIn("api_key", data)
        self.assertNotIn("encrypted_api_key", data)

    def test_enabled_without_base_url_is_400(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.patch(
            "/api/v2/admin/prowlarr",
            **_auth(),
            **_json({"enabled": True, "api_key": "key"}),
        )
        self.assertEqual(r.status_code, 400)

    def test_non_admin_forbidden(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.patch("/api/v2/admin/prowlarr", **_auth(_USER_TOKEN), **_json({}))
        self.assertEqual(r.status_code, 403)


class TestAdminProwlarrTest(unittest.TestCase):

    def test_success(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post("/api/v2/admin/prowlarr/test", **_auth())
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["version"], "1.28.0")
        self.assertEqual(data["active_indexers"], 5)

    def test_connection_failure(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientFail).test_client()
        r = client.post("/api/v2/admin/prowlarr/test", **_auth())
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("message", data)

    def test_not_configured(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.post("/api/v2/admin/prowlarr/test", **_auth())
        self.assertEqual(r.status_code, 400)
        data = r.get_json()
        self.assertEqual(data.get("code"), "PROWLARR_NOT_CONFIGURED")

    def test_non_admin_forbidden(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.post("/api/v2/admin/prowlarr/test", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 403)


# ── Me routes ─────────────────────────────────────────────────────────────────

class TestMeProwlarrGet(unittest.TestCase):

    def test_no_config_returns_none_and_unavailable(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/me/prowlarr", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIsNone(data["user_config"])
        self.assertEqual(data["effective_config_source"], "none")
        self.assertFalse(data["search_available"])

    def test_global_config_exists_fallback(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://g.example.com", api_key="gkey")
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/me/prowlarr", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIsNone(data["user_config"])
        self.assertEqual(data["effective_config_source"], "global")
        self.assertTrue(data["search_available"])

    def test_own_user_config_takes_priority(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://g.example.com", api_key="gkey")
        svc.save_user_config(
            user_id=_USER_ID,
            enabled=True,
            base_url="https://u.example.com",
            api_key="ukey",
        )
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/me/prowlarr", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIsNotNone(data["user_config"])
        self.assertEqual(data["effective_config_source"], "user")
        self.assertTrue(data["search_available"])
        self.assertNotIn("api_key", data["user_config"])
        self.assertNotIn("encrypted_api_key", data["user_config"])
        self.assertTrue(data["user_config"]["has_api_key"])


class TestMeProwlarrPatch(unittest.TestCase):

    def test_valid_update_returns_safe_dict(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.patch(
            "/api/v2/me/prowlarr",
            **_auth(_USER_TOKEN),
            **_json({"enabled": True, "base_url": "https://u.example.com", "api_key": "key"}),
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["has_api_key"])
        self.assertNotIn("api_key", data)

    def test_enabled_without_base_url_is_400(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.patch(
            "/api/v2/me/prowlarr",
            **_auth(_USER_TOKEN),
            **_json({"enabled": True, "api_key": "key"}),
        )
        self.assertEqual(r.status_code, 400)


class TestMeProwlarrTest(unittest.TestCase):

    def test_user_config_tested(self):
        svc, _, _ = _make_svc()
        svc.save_user_config(
            user_id=_USER_ID, enabled=True,
            base_url="https://u.example.com", api_key="ukey",
        )
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post("/api/v2/me/prowlarr/test", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["source"], "user")

    def test_global_config_fallback_tested(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://g.example.com", api_key="gkey")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post("/api/v2/me/prowlarr/test", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["source"], "global")

    def test_not_configured(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.post("/api/v2/me/prowlarr/test", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_NOT_CONFIGURED")

    def test_connection_failure_returns_ok_false(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://g.example.com", api_key="gkey")
        client = _make_app(svc, FakeProwlarrClientFail).test_client()
        r = client.post("/api/v2/me/prowlarr/test", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["ok"])


# ── Search routes ─────────────────────────────────────────────────────────────

class TestProwlarrStatus(unittest.TestCase):

    def test_configured_returns_available_true(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.get("/api/v2/prowlarr/status", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["available"])
        self.assertEqual(data["source"], "global")
        self.assertEqual(data["version"], "1.28.0")

    def test_not_configured_returns_available_false(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/prowlarr/status", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["available"])
        self.assertEqual(data["source"], "none")

    def test_configured_but_connection_fails(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientFail).test_client()
        r = client.get("/api/v2/prowlarr/status", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["available"])
        self.assertIn("error", data)


class TestProwlarrIndexers(unittest.TestCase):

    def test_configured_returns_list(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.get("/api/v2/prowlarr/indexers", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["name"], "Test Indexer")

    def test_not_configured_returns_400(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.get("/api/v2/prowlarr/indexers", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_NOT_CONFIGURED")

    def test_client_error_returns_502(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientFail).test_client()
        r = client.get("/api/v2/prowlarr/indexers", **_auth(_USER_TOKEN))
        self.assertEqual(r.status_code, 502)


class TestProwlarrSearch(unittest.TestCase):

    def test_valid_search_returns_results(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        cache = ProwlarrResultCache(ttl_minutes=5)
        client = _make_app(svc, FakeProwlarrClientOk, cache=cache).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu", "limit": 25}),
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["source"], "global")
        self.assertIsInstance(data["results"], list)
        self.assertEqual(len(data["results"]), 1)
        first = data["results"][0]
        self.assertEqual(first["title"], "Test Release")
        self.assertNotIn("api_key", first)
        # Sensitive URLs must never appear in response
        self.assertNotIn("download_url", first)
        self.assertNotIn("magnet_url", first)
        self.assertNotIn("info_url", first)
        # result_id and boolean flags must be present
        self.assertIn("result_id", first)
        self.assertIn("has_download", first)
        self.assertIn("has_magnet", first)
        self.assertIn("has_info_url", first)
        self.assertIn("has_real_magnet", first)
        self.assertIn("has_torrent_download", first)
        # source_debug must NOT appear in the public response
        self.assertNotIn("source_debug", first)
        # result_id must be cached server-side and user-isolated
        cached = cache.get(first["result_id"])
        self.assertIsNotNone(cached)
        self.assertEqual(cached.user_id, _USER_ID)

    def test_search_sensitive_urls_never_in_response(self):
        """Explicit regression: FakeProwlarrClientOk has real-looking sensitive URLs."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu"}),
        )
        self.assertEqual(r.status_code, 200)
        for result in r.get_json()["results"]:
            self.assertNotIn("download_url", result)
            self.assertNotIn("magnet_url", result)
            self.assertNotIn("info_url", result)

    def test_search_boolean_flags_reflect_presence(self):
        """All boolean source flags must be True when corresponding URLs are present."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu"}),
        )
        first = r.get_json()["results"][0]
        # FakeProwlarrClientOk supplies non-None URLs for all three fields:
        #   magnet_url=real magnet:?, download_url=HTTP, info_url=HTTP
        self.assertTrue(first["has_download"])
        self.assertTrue(first["has_magnet"])
        self.assertTrue(first["has_info_url"])
        # Clean source flags
        self.assertTrue(first["has_real_magnet"])
        self.assertTrue(first["has_torrent_download"])

    def test_get_for_user_isolates_by_user(self):
        """get_for_user() must return None when result belongs to a different user."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        cache = ProwlarrResultCache(ttl_minutes=5)
        client = _make_app(svc, FakeProwlarrClientOk, cache=cache).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu"}),
        )
        rid = r.get_json()["results"][0]["result_id"]
        # Correct user → found
        self.assertIsNotNone(cache.get_for_user(rid, _USER_ID))
        # Different user → None
        self.assertIsNone(cache.get_for_user(rid, "another-user-id"))

    def test_search_limit_invalid_falls_back_to_50(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu", "limit": "not-a-number"}),
        )
        self.assertEqual(r.status_code, 200)

    def test_search_limit_out_of_range_falls_back_to_50(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu", "limit": 9999}),
        )
        self.assertEqual(r.status_code, 200)

    def test_not_configured_returns_400(self):
        svc, _, _ = _make_svc()
        client = _make_app(svc).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu"}),
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_NOT_CONFIGURED")

    def test_client_error_returns_502(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientFail).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu"}),
        )
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_SEARCH_FAILED")

    def test_empty_query_with_period_all_returns_400(self):
        """Empty query + period=all is too broad — must be blocked (400)."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({}),  # no query, no period → defaults to period=all
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_EMPTY_QUERY_NO_PERIOD")

    def test_empty_query_with_period_all_and_category_returns_400(self):
        """Empty query + period=all + categories is still blocked — categories alone don't bypass."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"period": "all", "categories": [2000]}),
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_EMPTY_QUERY_NO_PERIOD")

    def test_empty_query_with_period_week_returns_200(self):
        """Empty query with a period scope is valid — returns recent results."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"period": "week"}),
        )
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json()["results"], list)

    def test_search_response_includes_pagination_fields(self):
        """Search response includes total_filtered, has_next, limit, offset."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu", "limit": 25}),
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("total_filtered", data)
        self.assertIn("has_next", data)
        self.assertIn("limit", data)
        self.assertIn("offset", data)

    def test_user_config_search_uses_user_source(self):
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://g.example.com", api_key="gkey")
        svc.save_user_config(
            user_id=_USER_ID, enabled=True,
            base_url="https://u.example.com", api_key="ukey",
        )
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu"}),
        )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["source"], "user")


class TestProwlarrPagination(unittest.TestCase):
    """
    Tests 37–44: local pagination and period filtering.

    FakeProwlarrClient60 returns 60 results with this date distribution:
       5  from 1h ago  (today, week, month)
      10  from 3d ago  (week, month)
      15  from 15d ago (month only)
      30  from 40d ago (old — only visible with period=all)
    """

    def _search(self, payload: dict) -> tuple[dict, dict]:
        """Run a search, return (response_body, captured_client_kwargs)."""
        captured: dict = {}

        class _CapturingClient60(FakeProwlarrClient60):
            def search(self, query, **kw):
                captured.update(kw)
                return super().search(query, **kw)

        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, client_factory=_CapturingClient60).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json(payload),
        )
        self.assertEqual(r.status_code, 200)
        return r.get_json(), captured

    def test_offset_never_sent_to_prowlarr(self):
        """Offset must never be forwarded to Prowlarr — pagination is local."""
        data, kw = self._search({"query": "ubuntu", "limit": 25, "offset": 0})
        self.assertNotIn("offset", kw)

    def test_offset_25_not_sent_to_prowlarr(self):
        """Even offset=25 must not be forwarded to Prowlarr."""
        data, kw = self._search({"query": "ubuntu", "limit": 25, "offset": 25})
        self.assertNotIn("offset", kw)

    def test_invalid_offset_defaults_to_zero(self):
        """Non-numeric or negative offset → defaults to 0, search succeeds."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClient60).test_client()
        for bad_offset in ["bad", -10]:
            r = client.post(
                "/api/v2/prowlarr/search",
                **_auth(_USER_TOKEN),
                **_json({"query": "ubuntu", "limit": 25, "offset": bad_offset}),
            )
            self.assertEqual(r.status_code, 200)

    # ── Local pagination against 60-result fake ──────────────────────────────

    def test_page0_returns_25_results_has_next_true(self):
        """period=all, limit=25, offset=0 → 25 results, has_next=True."""
        data, _ = self._search({"query": "ubuntu", "limit": 25, "offset": 0})
        self.assertEqual(len(data["results"]), 25)
        self.assertTrue(data["has_next"])
        self.assertEqual(data["total_filtered"], 60)

    def test_page1_returns_25_results_has_next_true(self):
        """period=all, limit=25, offset=25 → 25 results, has_next=True."""
        data, _ = self._search({"query": "ubuntu", "limit": 25, "offset": 25})
        self.assertEqual(len(data["results"]), 25)
        self.assertTrue(data["has_next"])

    def test_page2_returns_10_results_has_next_false(self):
        """period=all, limit=25, offset=50 → 10 remaining results, has_next=False."""
        data, _ = self._search({"query": "ubuntu", "limit": 25, "offset": 50})
        self.assertEqual(len(data["results"]), 10)
        self.assertFalse(data["has_next"])

    # ── Period filtering ─────────────────────────────────────────────────────

    def test_period_today_filters_correctly(self):
        """period=today → only results from 1h ago (5 results)."""
        data, _ = self._search({"query": "ubuntu", "period": "today", "limit": 100, "offset": 0})
        # 5 results from 1 hour ago are today; 3d/15d/40d results are not.
        self.assertEqual(data["total_filtered"], 5)
        self.assertFalse(data["has_next"])

    def test_period_week_filters_correctly(self):
        """period=week → 1h + 3d results = 5 + 10 = 15 results."""
        data, _ = self._search({"query": "ubuntu", "period": "week", "limit": 100, "offset": 0})
        self.assertEqual(data["total_filtered"], 15)

    def test_period_month_filters_correctly(self):
        """period=month → 1h + 3d + 15d results = 5 + 10 + 15 = 30 results."""
        data, _ = self._search({"query": "ubuntu", "period": "month", "limit": 100, "offset": 0})
        self.assertEqual(data["total_filtered"], 30)

    def test_period_all_returns_all_60(self):
        """period=all with a query → all 60 results."""
        data, _ = self._search({"query": "ubuntu", "period": "all", "limit": 100, "offset": 0})
        self.assertEqual(data["total_filtered"], 60)

    def test_no_sensitive_url_in_paged_results(self):
        """Sensitive URLs must not appear in any paged result."""
        data, _ = self._search({"query": "ubuntu", "limit": 25, "offset": 0})
        for r in data["results"]:
            self.assertNotIn("download_url", r)
            self.assertNotIn("magnet_url", r)
            self.assertNotIn("info_url", r)


class TestProwlarrSortAndPageCoherence(unittest.TestCase):
    """
    Verifies that the pipeline order is:
      1. fetch from Prowlarr (no offset)
      2. filter by period
      3. sort newest-first
      4. paginate locally
      5. return page + has_next / total_filtered

    FakeProwlarrClient60 date distribution (reminder):
       5  from 1h ago  → today, week, month
      10  from 3d ago  → week, month
      15  from 15d ago → month only
      30  from 40d ago → old (period=all only)
    """

    def _search(self, payload: dict) -> dict:
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClient60).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json(payload),
        )
        self.assertEqual(r.status_code, 200)
        return r.get_json()

    def _pub_dates(self, results: list) -> list:
        """Return ISO publish_dates from a result page (may be None for missing dates)."""
        return [r.get("publish_date") for r in results]

    def test_page0_newest_first_week(self):
        """period=week, page 0 — dates must be in descending order."""
        data = self._search({"query": "ubuntu", "period": "week", "limit": 10, "offset": 0})
        dates = [d for d in self._pub_dates(data["results"]) if d]
        parsed = [datetime.fromisoformat(d.replace("Z", "+00:00")) for d in dates]
        self.assertEqual(parsed, sorted(parsed, reverse=True),
                         "Page 0 results must be sorted newest-first")

    def test_page1_older_than_page0_week(self):
        """period=week, page 1 dates must all be ≤ oldest date on page 0."""
        data0 = self._search({"query": "ubuntu", "period": "week", "limit": 10, "offset": 0})
        data1 = self._search({"query": "ubuntu", "period": "week", "limit": 10, "offset": 10})
        dates0 = [datetime.fromisoformat(d.replace("Z", "+00:00"))
                  for d in self._pub_dates(data0["results"]) if d]
        dates1 = [datetime.fromisoformat(d.replace("Z", "+00:00"))
                  for d in self._pub_dates(data1["results"]) if d]
        if dates0 and dates1:
            self.assertLessEqual(max(dates1), min(dates0),
                                 "Page 1 dates must be ≤ oldest date on page 0")

    def test_page0_newest_first_month(self):
        """period=month, page 0 — dates must be in descending order."""
        data = self._search({"query": "ubuntu", "period": "month", "limit": 10, "offset": 0})
        dates = [d for d in self._pub_dates(data["results"]) if d]
        parsed = [datetime.fromisoformat(d.replace("Z", "+00:00")) for d in dates]
        self.assertEqual(parsed, sorted(parsed, reverse=True),
                         "Page 0 results must be sorted newest-first")

    def test_page1_no_artificial_empty_month(self):
        """period=month has 30 total — page 1 (offset=10, limit=10) must return 10 results."""
        data = self._search({"query": "ubuntu", "period": "month", "limit": 10, "offset": 10})
        self.assertEqual(len(data["results"]), 10,
                         "Page 1 of month filter must not be artificially empty")
        self.assertTrue(data["has_next"])

    def test_page2_no_artificial_empty_month(self):
        """period=month page 2 (offset=20, limit=10) must return 10 results."""
        data = self._search({"query": "ubuntu", "period": "month", "limit": 10, "offset": 20})
        self.assertEqual(len(data["results"]), 10)
        self.assertFalse(data["has_next"])

    def test_has_next_based_on_total_filtered_not_raw(self):
        """has_next must reflect total_filtered, not raw Prowlarr count."""
        # period=today → 5 filtered results; limit=3, offset=0 → has_next=True
        data = self._search({"query": "ubuntu", "period": "today", "limit": 3, "offset": 0})
        self.assertEqual(data["total_filtered"], 5)
        self.assertTrue(data["has_next"])
        # limit=3, offset=3 → 2 remaining → has_next=False
        data2 = self._search({"query": "ubuntu", "period": "today", "limit": 3, "offset": 3})
        self.assertEqual(len(data2["results"]), 2)
        self.assertFalse(data2["has_next"])

    def test_cross_page_dates_coherent_all(self):
        """period=all (with query), pages 0/1/2 — last date on page N must be ≥ first date on page N+1."""
        pages = [
            self._search({"query": "ubuntu", "period": "all", "limit": 25, "offset": 0}),
            self._search({"query": "ubuntu", "period": "all", "limit": 25, "offset": 25}),
            self._search({"query": "ubuntu", "period": "all", "limit": 25, "offset": 50}),
        ]
        all_dates = []
        for p in pages:
            for r in p["results"]:
                d = r.get("publish_date")
                if d:
                    all_dates.append(datetime.fromisoformat(d.replace("Z", "+00:00")))
        # The full 60-result sequence must be non-increasing
        self.assertEqual(all_dates, sorted(all_dates, reverse=True),
                         "Cross-page dates must be globally newest-first")


class TestProwlarrFilterPassthroughEmptyQuery(unittest.TestCase):
    """
    Tests 45–49: categories and indexer_ids must reach the Prowlarr client
    unchanged when query is empty and a period limiter (today/week/month) is set.
    """

    def _search_with_capture(self, payload: dict) -> tuple[int, dict, dict]:
        """
        Return (status_code, response_body, captured_kwargs).
        captured_kwargs records the keyword arguments passed to client.search().
        """
        captured: dict = {}

        class _CapturingClient:
            def __init__(self, base_url: str, api_key: str):
                pass

            def search(self, query: str, **kw) -> list:
                captured["query"] = query
                captured["categories"] = kw.get("categories")
                captured["indexer_ids"] = kw.get("indexer_ids")
                return []

        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, client_factory=_CapturingClient).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json(payload),
        )
        return r.status_code, r.get_json(), captured

    def test_empty_query_period_week_passes_categories(self):
        """45. Empty query + period=week + categories=[2000] → client receives categories=[2000]."""
        status, _, captured = self._search_with_capture(
            {"period": "week", "categories": [2000]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(captured.get("categories"), [2000])

    def test_empty_query_period_month_passes_indexer_ids(self):
        """46. Empty query + period=month + indexer_ids=[1] → client receives indexer_ids=[1]."""
        status, _, captured = self._search_with_capture(
            {"period": "month", "indexer_ids": [1]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(captured.get("indexer_ids"), [1])

    def test_empty_query_period_today_passes_both_filters(self):
        """47. Empty query + period=today + both filters → both forwarded to client."""
        status, _, captured = self._search_with_capture(
            {"period": "today", "categories": [2000], "indexer_ids": [1]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(captured.get("categories"), [2000])
        self.assertEqual(captured.get("indexer_ids"), [1])

    def test_empty_query_period_all_with_filters_still_400(self):
        """48. Empty query + period=all + filters → 400; client is never invoked."""
        status, body, captured = self._search_with_capture(
            {"period": "all", "categories": [2000], "indexer_ids": [1]}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("code"), "PROWLARR_EMPTY_QUERY_NO_PERIOD")
        # The route must have returned before ever calling the client.
        self.assertNotIn("categories", captured)

    def test_no_filters_passes_none_to_client(self):
        """49. No categories/indexer_ids → client receives None for both (= all)."""
        status, _, captured = self._search_with_capture({"query": "ubuntu"})
        self.assertEqual(status, 200)
        self.assertIsNone(captured.get("categories"))
        self.assertIsNone(captured.get("indexer_ids"))


class TestProwlarrClientValidation(unittest.TestCase):

    def test_invalid_scheme_raises(self):
        """base_url with non-http(s) scheme must be rejected by the client."""
        from backend.clients.prowlarr_client import ProwlarrClient
        with self.assertRaises(ValueError):
            ProwlarrClient("ftp://bad.example.com", "key")

    def test_empty_base_url_raises(self):
        from backend.clients.prowlarr_client import ProwlarrClient
        with self.assertRaises(ValueError):
            ProwlarrClient("", "key")

    def test_valid_http_accepted(self):
        from backend.clients.prowlarr_client import ProwlarrClient
        # Should not raise
        c = ProwlarrClient("http://prowlarr.local:9696", "key")
        self.assertIsNotNone(c)

    def test_valid_https_accepted(self):
        from backend.clients.prowlarr_client import ProwlarrClient
        c = ProwlarrClient("https://prowlarr.example.com", "key")
        self.assertIsNotNone(c)


class TestProwlarrCacheUnavailable(unittest.TestCase):

    def test_search_returns_503_when_no_cache(self):
        """If PROWLARR_RESULT_CACHE_V2 is absent, search must return 503 — no raw URL leak."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")

        app = Flask(__name__)
        app.config["TESTING"] = True
        app.config["SETTINGS"] = FakeSettings()
        app.config["API_TOKEN_REPO_V2"] = FakeTokenRepo()
        app.config["USER_REPO_V2"] = FakeUserRepo()
        app.config["PROWLARR_CONFIG_SERVICE_V2"] = svc
        app.config["PROWLARR_CLIENT_FACTORY"] = FakeProwlarrClientOk
        # Deliberately do NOT set PROWLARR_RESULT_CACHE_V2
        app.register_blueprint(prowlarr_search_bp)

        @app.errorhandler(ApiAuthError)
        def handle_auth(e):
            return {"error": e.message}, 401

        client = app.test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({"query": "ubuntu"}),
        )
        self.assertEqual(r.status_code, 503)
        body = r.get_json()
        self.assertEqual(body.get("code"), "PROWLARR_CACHE_UNAVAILABLE")
        self.assertNotIn("download_url", body)
        self.assertNotIn("magnet_url", body)
        self.assertNotIn("info_url", body)


# ── Public source flags tests ─────────────────────────────────────────────────

class TestPublicSourceFlags(unittest.TestCase):
    """
    has_real_magnet and has_torrent_download must accurately reflect actual
    magnet:? availability and HTTP torrent download availability.
    source_debug must NOT appear in any search result.
    """

    def _search_first(
        self,
        *,
        guid: str = "guid-001",
        magnet_url: str | None = None,
        download_url: str | None = None,
        info_url: str | None = None,
    ) -> dict:
        """Run a search with a controlled single result and return the result dict."""
        class _FakeClient:
            def __init__(self, base_url, api_key): pass
            def search(self, query, **kw):
                return [{
                    "guid": guid,
                    "title": "Test Release",
                    "indexer": "Test Indexer",
                    "indexer_id": 1,
                    "size": 1_000_000,
                    "seeders": 10,
                    "leechers": 2,
                    "publish_date": "2026-06-10T00:00:00Z",
                    "categories": [],
                    "magnet_url": magnet_url,
                    "download_url": download_url,
                    "info_url": info_url,
                }]

        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        app = _make_app(svc, client_factory=_FakeClient)
        with app.test_client() as c:
            r = c.post(
                "/api/v2/prowlarr/search",
                **_json({"query": "test"}),
                **_auth(_USER_TOKEN),
            )
        self.assertEqual(r.status_code, 200)
        results = r.get_json()["results"]
        self.assertEqual(len(results), 1)
        return results[0]

    def test_source_debug_absent_from_results(self):
        """Regression: source_debug must NOT appear in any search result."""
        result = self._search_first(
            magnet_url="magnet:?xt=urn:btih:abc&tr=udp://tracker.example.com",
        )
        self.assertNotIn("source_debug", result)

    def test_real_magnet_in_magnet_url(self):
        """magnet_url contains a real magnet:? → has_real_magnet=True."""
        result = self._search_first(
            magnet_url="magnet:?xt=urn:btih:abc123&dn=test",
            download_url="https://indexer.example.com/download?apikey=SECRET",
        )
        self.assertTrue(result["has_real_magnet"])
        self.assertTrue(result["has_torrent_download"])

    def test_real_magnet_in_guid(self):
        """guid contains the real magnet:? (not magnet_url) → has_real_magnet=True."""
        result = self._search_first(
            guid="magnet:?xt=urn:btih:abc123&dn=test",
            magnet_url=None,
            download_url=None,
        )
        self.assertTrue(result["has_real_magnet"])
        self.assertFalse(result["has_torrent_download"])

    def test_https_redirect_in_magnet_url_is_not_real_magnet(self):
        """HTTPS redirect URL in magnet_url → has_real_magnet=False."""
        result = self._search_first(
            magnet_url="https://indexer.example.com/redirect?apikey=SECRETTOKEN",
            download_url=None,
        )
        self.assertFalse(result["has_real_magnet"])

    def test_http_download_url_sets_torrent_download(self):
        """HTTP(S) download_url → has_torrent_download=True."""
        result = self._search_first(
            download_url="https://indexer.example.com/download?token=SECRET",
        )
        self.assertTrue(result["has_torrent_download"])

    def test_magnet_in_download_url_not_torrent_download(self):
        """magnet:? in download_url → has_torrent_download=False but has_real_magnet=True."""
        result = self._search_first(
            magnet_url=None,
            download_url="magnet:?xt=urn:btih:abc123&dn=test",
        )
        self.assertFalse(result["has_torrent_download"])
        self.assertTrue(result["has_real_magnet"])

    def test_all_empty_both_false(self):
        """No URLs anywhere → has_real_magnet=False, has_torrent_download=False."""
        result = self._search_first(guid="not-a-url", magnet_url=None, download_url=None)
        self.assertFalse(result["has_real_magnet"])
        self.assertFalse(result["has_torrent_download"])


class TestProwlarrClientSearchParams(unittest.TestCase):
    """
    Tests 50–54: ProwlarrClient.search() must encode multi-value filters as
    repeated HTTP query params, not comma-separated values or bracket notation.

    Prowlarr rejects indexerIds=1,2 (400) but accepts indexerIds=1&indexerIds=2 (200).
    Same rule applies to categories params (categories=2000&categories=5000).
    """

    def _capture_params(self, **search_kwargs) -> list[tuple[str, str]]:
        """
        Call ProwlarrClient.search() with a mocked requests.get.
        Returns the params list received by the mock.
        """
        from backend.clients.prowlarr_client import ProwlarrClient

        captured: list = []

        def _fake_get(url, *, params=None, headers=None, timeout=None):
            if params is not None:
                captured.extend(params)
            mock_resp = MagicMock()
            mock_resp.json.return_value = []
            mock_resp.raise_for_status.return_value = None
            return mock_resp

        client = ProwlarrClient("http://prowlarr.test:9696", "test-key")
        with patch("backend.clients.prowlarr_client.requests.get", side_effect=_fake_get):
            client.search("test", **search_kwargs)

        return captured

    def test_indexer_ids_sent_as_repeated_params(self):
        """50. indexer_ids=[1,2] → two separate indexerIds params, not indexerIds=1,2."""
        params = self._capture_params(indexer_ids=[1, 2])
        ids = [(k, v) for k, v in params if k == "indexerIds"]
        self.assertEqual(len(ids), 2)
        self.assertIn(("indexerIds", "1"), ids)
        self.assertIn(("indexerIds", "2"), ids)

    def test_categories_sent_as_repeated_params(self):
        """51. categories=[2000,5000] → two separate categories params, not categories=2000,5000."""
        params = self._capture_params(categories=[2000, 5000])
        cats = [(k, v) for k, v in params if k == "categories"]
        self.assertEqual(len(cats), 2)
        self.assertIn(("categories", "2000"), cats)
        self.assertIn(("categories", "5000"), cats)

    def test_mixed_filters_four_repeated_params(self):
        """52. indexer_ids=[1,2] + categories=[2000,5000] → four repeated params total."""
        params = self._capture_params(indexer_ids=[1, 2], categories=[2000, 5000])
        ids = [(k, v) for k, v in params if k == "indexerIds"]
        cats = [(k, v) for k, v in params if k == "categories"]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(cats), 2)

    def test_no_offset_param_sent(self):
        """53. offset must never appear in HTTP params sent to Prowlarr."""
        params = self._capture_params(indexer_ids=[1])
        keys = {k for k, v in params}
        self.assertNotIn("offset", keys)
        self.assertNotIn("Offset", keys)

    def test_no_wrong_param_names(self):
        """54. Old/wrong names (Categories[], IndexerIds[], category, indexer_ids) must not appear."""
        params = self._capture_params(categories=[2000], indexer_ids=[1])
        keys = {k for k, v in params}
        for wrong in ("Categories[]", "IndexerIds[]", "category", "indexer_ids", "offset", "Offset"):
            self.assertNotIn(wrong, keys, f"wrong param {wrong!r} must not be sent to Prowlarr")


if __name__ == "__main__":
    unittest.main(verbosity=2)
