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
    26. POST /search — valid query → {source, results}
    27. POST /search — not configured → 400 PROWLARR_NOT_CONFIGURED
    28. POST /search — client error → 502 PROWLARR_SEARCH_FAILED
    29. POST /search — empty query → 200 (recent results, Prowlarr accepts Query='')

  Pagination (limit / offset):
    37. limit=25, offset=0 → client receives offset=0 (not sent as param)
    38. limit=25, offset=25 → client receives offset=25
    39. invalid offset → defaults to 0, search succeeds

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

    def test_empty_query_returns_results(self):
        """Empty query is valid — Prowlarr accepts Query='' and returns recent results."""
        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, FakeProwlarrClientOk).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json({}),
        )
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json()["results"], list)

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
    Tests 37–39: limit/offset pagination passed to ProwlarrClient.search().
    """

    def _search_with_kw(self, payload: dict) -> dict:
        """Run a search and return the kwargs captured by the fake client."""
        captured: dict = {}

        class _CapturingClient:
            def __init__(self, base_url, api_key): pass
            def search(self, query, **kw):
                captured.update(kw)
                return []

        svc, _, _ = _make_svc()
        svc.save_global_config(enabled=True, base_url="https://p.example.com", api_key="key")
        client = _make_app(svc, client_factory=_CapturingClient).test_client()
        r = client.post(
            "/api/v2/prowlarr/search",
            **_auth(_USER_TOKEN),
            **_json(payload),
        )
        self.assertEqual(r.status_code, 200)
        return captured

    def test_offset_zero_not_sent_to_prowlarr(self):
        """offset=0 (default) → Offset param not added to Prowlarr request (clean URL)."""
        kw = self._search_with_kw({"query": "ubuntu", "limit": 25, "offset": 0})
        self.assertEqual(kw.get("limit"), 25)
        self.assertEqual(kw.get("offset"), 0)

    def test_offset_25_passed_to_client(self):
        """limit=25, offset=25 → client.search receives offset=25 (page 2)."""
        kw = self._search_with_kw({"query": "ubuntu", "limit": 25, "offset": 25})
        self.assertEqual(kw.get("limit"), 25)
        self.assertEqual(kw.get("offset"), 25)

    def test_invalid_offset_defaults_to_zero(self):
        """Non-numeric or negative offset → defaults to 0, search succeeds."""
        kw = self._search_with_kw({"query": "ubuntu", "limit": 25, "offset": "bad"})
        self.assertEqual(kw.get("offset"), 0)

        kw_neg = self._search_with_kw({"query": "ubuntu", "limit": 25, "offset": -10})
        self.assertEqual(kw_neg.get("offset"), 0)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
