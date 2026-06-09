#!/usr/bin/env python3
"""
Unit tests: Prowlarr Bloc 4 — POST /api/v2/prowlarr/jobs.

Covers:
  1.  Valid result_id, default destination configured → job created with destination
  2.  Valid result_id, magnet preferred over download_url
  3.  Valid result_id, download_url fallback (no magnet)
  4.  No default destination → falls back to links-only (not an error)
  5.  Explicit destination_config_id in request → used directly
  6.  Missing result_id → 400
  7.  Empty result_id → 400
  8.  Expired / unknown result_id → 404 PROWLARR_RESULT_NOT_FOUND
  9.  Wrong user (isolation) → 404 PROWLARR_RESULT_NOT_FOUND
  10. Result with no URLs → 400 PROWLARR_NO_URL
  11. Cache unavailable → 503 PROWLARR_CACHE_UNAVAILABLE
  12. Response body never contains sensitive URL fields
  13. Response fields are exactly {id, status, source_type}
  14. Job service ValueError (provider error) → 400
  15. Destination disabled error → 400 (via _handle_destination_exception)

Run from project root:
    python3 scripts/tests/unit/test_prowlarr_bloc4_create_job.py
"""

import json
import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask

from backend.models.user import User
from backend.routes_v2.prowlarr_search import prowlarr_search_bp
from backend.services_v2.prowlarr_result_cache import ProwlarrResultCache
from backend.services_v2.destination_factory import (
    DestinationConfigNotFoundError,
    DestinationConfigDisabledError,
)
from backend.utils.time import utc_now_iso

# ── Constants ─────────────────────────────────────────────────────────────────

_SUPER_TOKEN = "tok-super"
_USER_TOKEN = "tok-user"
_OTHER_TOKEN = "tok-other"
_SUPER_ID = "user-super"
_USER_ID = "user-regular"
_OTHER_ID = "user-other"

_MAGNET = "magnet:?xt=urn:btih:deadbeef00000000000000000000000000000000&dn=test&tr=udp%3A%2F%2Ftracker.example.com"
_DOWNLOAD_URL = "https://indexer.example.com/download/abc?apikey=SECRETTOKEN&passkey=HIDDEN"


# ── Auth fakes ────────────────────────────────────────────────────────────────

class _FakeApiToken:
    def __init__(self, user_id: str):
        self.user_id = user_id


class FakeTokenRepo:
    def get_active_by_token(self, token: str):
        mapping = {_SUPER_TOKEN: _SUPER_ID, _USER_TOKEN: _USER_ID, _OTHER_TOKEN: _OTHER_ID}
        uid = mapping.get(token)
        return _FakeApiToken(uid) if uid else None


class FakeUserRepo:
    def get_by_id(self, uid: str) -> User | None:
        ts = utc_now_iso()
        roles = {_SUPER_ID: "super_admin", _USER_ID: "user", _OTHER_ID: "user"}
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


# ── Job fakes ─────────────────────────────────────────────────────────────────

class FakeJob:
    def __init__(self, source_type: str = "magnet", source_value: str = ""):
        self.id = "fake-job-001"
        self.status = "pending"
        self.source_type = source_type
        self.source_value = source_value


class FakeJobService:
    def __init__(self, *, raise_exc=None):
        self._raise = raise_exc
        self.last_create_kwargs: dict = {}

    def create_job(self, context, source_type, source_value, **kwargs):
        self.last_create_kwargs = {"source_type": source_type, "source_value": source_value, **kwargs}
        if self._raise:
            raise self._raise
        return FakeJob(source_type=source_type, source_value=source_value)


# ── Destination factory fakes ─────────────────────────────────────────────────

class _FakeResolvedConfig:
    def __init__(self, config_id: str):
        self.id = config_id


class _FakeResolved:
    def __init__(self, config_id: str):
        self.config = _FakeResolvedConfig(config_id)

    @property
    def destination_config_id(self) -> str:
        return self.config.id


class FakeDestinationFactory:
    """Returns a default destination if `default_config_id` is set, otherwise raises NotFound."""

    def __init__(self, default_config_id: str | None = None):
        self._config_id = default_config_id

    def resolve_destination_for_user(self, user_id: str, destination_name=None, **kwargs):
        if self._config_id is None:
            raise DestinationConfigNotFoundError("No default destination configured")
        return _FakeResolved(self._config_id)


# ── Settings fake ─────────────────────────────────────────────────────────────

class _FakeSettings:
    LINK2NAS_SINGLE_USER_MODE = False


# ── App factory ───────────────────────────────────────────────────────────────

def _make_app(
    cache: ProwlarrResultCache | None = None,
    job_service: FakeJobService | None = None,
    destination_factory: FakeDestinationFactory | None = None,
) -> Flask:
    if destination_factory is None:
        destination_factory = FakeDestinationFactory(default_config_id=None)  # no default
    app = Flask(__name__)
    app.config.update({
        "SETTINGS": _FakeSettings(),
        "API_TOKEN_REPO_V2": FakeTokenRepo(),
        "USER_REPO_V2": FakeUserRepo(),
        "PROWLARR_RESULT_CACHE_V2": cache,
        "JOB_SERVICE_V2": job_service or FakeJobService(),
        "USER_DESTINATION_FACTORY_V2": destination_factory,
        "PROWLARR_CONFIG_SERVICE_V2": None,
        "PROWLARR_CLIENT_FACTORY": None,
    })
    app.register_blueprint(prowlarr_search_bp)
    return app


def _auth(token: str) -> dict:
    return {"X-Api-Key": token}


def _post_jobs(client, payload: dict, token: str = _USER_TOKEN):
    return client.post(
        "/api/v2/prowlarr/jobs",
        data=json.dumps(payload),
        content_type="application/json",
        headers=_auth(token),
    )


# ── Cache helper ──────────────────────────────────────────────────────────────

def _make_cache_with_result(
    user_id: str = _USER_ID,
    magnet_url: str | None = _MAGNET,
    download_url: str | None = None,
    info_url: str | None = None,
) -> tuple[ProwlarrResultCache, str]:
    """Returns (cache, result_id)."""
    cache = ProwlarrResultCache(ttl_minutes=5)
    raw = [{
        "guid": "test-guid-1",
        "title": "Test Release",
        "indexer": "TestIndexer",
        "size": 1_500_000_000,
        "seeders": 42,
        "categories": [2000],
        "download_url": download_url,
        "magnet_url": magnet_url,
        "info_url": info_url,
    }]
    safe = cache.store_results(raw, user_id)
    result_id = safe[0]["result_id"]
    return cache, result_id


# ── Tests: destination resolution ─────────────────────────────────────────────

class TestCreateJobDestinationResolution(unittest.TestCase):

    def test_default_destination_used_when_available(self):
        """When user has a default destination, job is created with that destination_config_id."""
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService()
        dest_factory = FakeDestinationFactory(default_config_id="dest-001")
        app = _make_app(cache=cache, job_service=svc, destination_factory=dest_factory)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(svc.last_create_kwargs.get("destination_config_id"), "dest-001")

    def test_no_default_destination_falls_back_links_only(self):
        """When no default destination exists, job is created links-only (not an error)."""
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService()
        dest_factory = FakeDestinationFactory(default_config_id=None)  # no default
        app = _make_app(cache=cache, job_service=svc, destination_factory=dest_factory)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        self.assertIsNone(svc.last_create_kwargs.get("destination_config_id"))
        self.assertIsNone(svc.last_create_kwargs.get("destination_name"))

    def test_explicit_destination_config_id_bypasses_factory(self):
        """An explicit destination_config_id in the request is used directly."""
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService()
        # Factory would raise NotFound, but explicit id takes precedence
        dest_factory = FakeDestinationFactory(default_config_id=None)
        app = _make_app(cache=cache, job_service=svc, destination_factory=dest_factory)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id, "destination_config_id": "explicit-dest"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(svc.last_create_kwargs.get("destination_config_id"), "explicit-dest")

    def test_destination_disabled_returns_error(self):
        """DestinationConfigDisabledError from create_job propagates as 400."""
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService(raise_exc=DestinationConfigDisabledError("Destination is disabled"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 400)
        body = r.get_json()
        self.assertIn("error", body)


# ── Tests: URL preference ─────────────────────────────────────────────────────

class TestCreateJobUrlPreference(unittest.TestCase):

    def test_magnet_preferred_over_download_url(self):
        """When result has both magnet_url and download_url, magnet is used."""
        cache, result_id = _make_cache_with_result(magnet_url=_MAGNET, download_url=_DOWNLOAD_URL)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["source_type"], "magnet")
        self.assertEqual(svc.last_create_kwargs["source_value"], _MAGNET)

    def test_download_url_used_when_no_magnet(self):
        """When result has no magnet_url, falls back to download_url."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["source_type"], "direct_link")
        self.assertEqual(svc.last_create_kwargs["source_value"], _DOWNLOAD_URL)

    def test_no_url_returns_400(self):
        """Result with neither magnet_url nor download_url returns PROWLARR_NO_URL."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=None)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 400)
        body = r.get_json()
        self.assertEqual(body.get("code"), "PROWLARR_NO_URL")


# ── Tests: validation ─────────────────────────────────────────────────────────

class TestCreateJobValidation(unittest.TestCase):

    def test_missing_result_id_returns_400(self):
        cache = ProwlarrResultCache(ttl_minutes=5)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {})
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    def test_empty_result_id_returns_400(self):
        cache = ProwlarrResultCache(ttl_minutes=5)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": "  "})
        self.assertEqual(r.status_code, 400)

    def test_expired_result_id_returns_404(self):
        cache = ProwlarrResultCache(ttl_minutes=5)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": "nonexistent-result-id"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_RESULT_NOT_FOUND")

    def test_cache_unavailable_returns_503(self):
        app = _make_app(cache=None)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": "any-id"})
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_CACHE_UNAVAILABLE")


# ── Tests: user isolation ─────────────────────────────────────────────────────

class TestCreateJobUserIsolation(unittest.TestCase):

    def test_wrong_user_cannot_use_result(self):
        """User B cannot create a job from User A's cached result."""
        cache, result_id = _make_cache_with_result(user_id=_USER_ID)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id}, token=_OTHER_TOKEN)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_RESULT_NOT_FOUND")

    def test_correct_user_can_use_result(self):
        """User A can create a job from their own cached result."""
        cache, result_id = _make_cache_with_result(user_id=_USER_ID)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id}, token=_USER_TOKEN)
        self.assertEqual(r.status_code, 201)


# ── Tests: security — no sensitive URL leakage ────────────────────────────────

class TestCreateJobSensitiveFields(unittest.TestCase):

    def test_response_never_exposes_sensitive_urls(self):
        """Response body must not contain download_url, magnet_url, or info_url."""
        cache, result_id = _make_cache_with_result(
            magnet_url=_MAGNET,
            download_url=_DOWNLOAD_URL,
            info_url="https://tracker.example.com/info/abc",
        )
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertNotIn("download_url", body)
        self.assertNotIn("magnet_url", body)
        self.assertNotIn("info_url", body)
        raw = r.data.decode()
        self.assertNotIn("SECRETTOKEN", raw)
        self.assertNotIn("HIDDEN", raw)

    def test_response_fields_are_exactly_id_status_source_type(self):
        cache, result_id = _make_cache_with_result()
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(set(body.keys()), {"id", "status", "source_type"})


# ── Tests: service errors ─────────────────────────────────────────────────────

class TestCreateJobServiceErrors(unittest.TestCase):

    def test_service_value_error_returns_400(self):
        """ValueError from the job service (provider not found) returns 400."""
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService(raise_exc=ValueError("No active provider configured"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 400)
        self.assertIn("No active provider", r.get_json().get("error", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
