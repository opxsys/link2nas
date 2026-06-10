#!/usr/bin/env python3
"""
Unit tests: Prowlarr Bloc 4 — POST /api/v2/prowlarr/jobs.

Covers:
  Destination resolution:
    1.  Default destination configured → job uses it.
    2.  No default destination → links-only (not an error).
    3.  Explicit destination_config_id in request → used directly.
    4.  Destination disabled → 400.

  URL handling (magnet):
    5.  magnet_url present → magnet job created (never direct_link).
    6.  magnet preferred over download_url when both present.

  URL handling (download_url only — server-side torrent fetch):
    7.  download_url present, backend fetches valid .torrent → torrent_file job.
    8.  download_url returns 404 → 502 PROWLARR_TORRENT_NOT_FOUND.
    9.  download_url returns HTTP 500 → 502 PROWLARR_DOWNLOAD_FAILED.
    10. download_url returns non-torrent content → 422 PROWLARR_INVALID_TORRENT.
    11. download_url fetch times out → 502 PROWLARR_DOWNLOAD_TIMEOUT.
    12. download_url is NEVER passed to the job service / provider.

  No URL:
    13. Neither magnet_url nor download_url → 400 PROWLARR_NO_URL.

  Validation:
    14. Missing result_id → 400.
    15. Empty result_id → 400.
    16. Expired / unknown result_id → 404 PROWLARR_RESULT_NOT_FOUND.
    17. Cache unavailable → 503 PROWLARR_CACHE_UNAVAILABLE.

  User isolation:
    18. Wrong user cannot use another user's result → 404.
    19. Correct user can use their own result.

  Security:
    20. Response never contains download_url, magnet_url, info_url.
    21. Response fields are exactly {id, status, source_type}.

  Service errors:
    22. ValueError from job service → 400.

Run from project root:
    python3 scripts/tests/unit/test_prowlarr_bloc4_create_job.py
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import requests as _requests_lib

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
_USER_TOKEN  = "tok-user"
_OTHER_TOKEN = "tok-other"
_SUPER_ID    = "user-super"
_USER_ID     = "user-regular"
_OTHER_ID    = "user-other"

_MAGNET = (
    "magnet:?xt=urn:btih:deadbeef00000000000000000000000000000000"
    "&dn=test&tr=udp%3A%2F%2Ftracker.example.com"
)
_DOWNLOAD_URL = "https://indexer.example.com/download/abc?apikey=SECRETTOKEN&passkey=HIDDEN"
_VALID_TORRENT = b"d8:announce35:udp://tracker.example.com:80/announcee"


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


# ── Settings fake ─────────────────────────────────────────────────────────────

class _FakeSettings:
    LINK2NAS_SINGLE_USER_MODE = False
    TEMP_DIR = tempfile.gettempdir()


# ── Job fakes ─────────────────────────────────────────────────────────────────

class FakeJob:
    def __init__(self, source_type: str = "magnet", source_value: str = ""):
        self.id = "fake-job-001"
        self.user_id = _USER_ID
        self.status = "pending"
        self.source_type = source_type
        self.source_value = source_value
        self.provider_payload_json = None
        self.provider_config_id = None
        self.provider_name = None
        self.provider_profile_name = None
        self.provider_resource_id = None
        self.provider_status = None
        self.error_message = None
        self.updated_at = "2025-01-01T00:00:00Z"
        self.started_at = None


class FakeJobService:
    def __init__(self, *, raise_exc=None, start_raise=None):
        self._raise = raise_exc
        self._start_raise = start_raise
        self.last_create_kwargs: dict = {}
        self.last_torrent_kwargs: dict = {}
        self.last_start_job_id: str | None = None
        self.job_repository = MagicMock()

    def create_job(self, context, source_type, source_value, **kwargs):
        self.last_create_kwargs = {
            "source_type": source_type,
            "source_value": source_value,
            **kwargs,
        }
        if self._raise:
            raise self._raise
        return FakeJob(source_type=source_type, source_value=source_value)

    def create_torrent_file_job(self, context, uploaded_path, **kwargs):
        self.last_torrent_kwargs = {"uploaded_path": uploaded_path, **kwargs}
        if self._raise:
            raise self._raise
        return FakeJob(source_type="torrent_file", source_value="torrent:fakehash"), False

    def start_job(self, context, job_id):
        self.last_start_job_id = job_id
        if self._start_raise:
            raise self._start_raise
        # Preserve source_type from whichever create path was used.
        if self.last_torrent_kwargs:
            source_type = "torrent_file"
        else:
            source_type = self.last_create_kwargs.get("source_type", "magnet")
        started = FakeJob(source_type=source_type)
        started.id = job_id
        started.status = "queued"
        return started


# ── Destination factory fakes ─────────────────────────────────────────────────

class _FakeResolvedConfig:
    def __init__(self, cid: str):
        self.id = cid


class _FakeResolved:
    def __init__(self, cid: str):
        self.config = _FakeResolvedConfig(cid)

    @property
    def destination_config_id(self) -> str:
        return self.config.id


class FakeDestinationFactory:
    def __init__(self, default_config_id: str | None = None):
        self._config_id = default_config_id

    def resolve_destination_for_user(self, user_id: str, destination_name=None, **kwargs):
        if self._config_id is None:
            raise DestinationConfigNotFoundError("No default destination configured")
        return _FakeResolved(self._config_id)


# ── App factory ───────────────────────────────────────────────────────────────

def _make_app(
    cache: ProwlarrResultCache | None = None,
    job_service: FakeJobService | None = None,
    destination_factory: FakeDestinationFactory | None = None,
) -> Flask:
    if destination_factory is None:
        destination_factory = FakeDestinationFactory(default_config_id=None)
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
    title: str = "Test Release",
) -> tuple[ProwlarrResultCache, str]:
    cache = ProwlarrResultCache(ttl_minutes=5)
    raw = [{
        "guid": "test-guid-1",
        "title": title,
        "indexer": "TestIndexer",
        "size": 1_500_000_000,
        "seeders": 42,
        "categories": [2000],
        "download_url": download_url,
        "magnet_url": magnet_url,
        "info_url": info_url,
    }]
    safe = cache.store_results(raw, user_id)
    return cache, safe[0]["result_id"]


def _mock_http_ok(content: bytes = _VALID_TORRENT):
    """Return a mock requests.get that returns `content` with status 200."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = content
    mock_get = MagicMock(return_value=mock_resp)
    return mock_get


def _mock_http_status(status_code: int):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.content = b""
    return MagicMock(return_value=mock_resp)


# ── Tests: destination resolution ─────────────────────────────────────────────

class TestDestinationResolution(unittest.TestCase):

    def test_default_destination_used_when_available(self):
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc,
                        destination_factory=FakeDestinationFactory("dest-001"))
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(svc.last_create_kwargs.get("destination_config_id"), "dest-001")

    def test_no_default_destination_falls_back_links_only(self):
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc,
                        destination_factory=FakeDestinationFactory(None))
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        self.assertIsNone(svc.last_create_kwargs.get("destination_config_id"))
        self.assertIsNone(svc.last_create_kwargs.get("destination_name"))

    def test_explicit_destination_config_id_bypasses_factory(self):
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc,
                        destination_factory=FakeDestinationFactory(None))
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id, "destination_config_id": "explicit-dest"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(svc.last_create_kwargs.get("destination_config_id"), "explicit-dest")

    def test_destination_disabled_returns_400(self):
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService(raise_exc=DestinationConfigDisabledError("Destination disabled"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())


# ── Tests: magnet path ────────────────────────────────────────────────────────

class TestMagnetPath(unittest.TestCase):

    def test_magnet_creates_magnet_job(self):
        """magnet_url → job of type magnet, not direct_link."""
        cache, result_id = _make_cache_with_result(magnet_url=_MAGNET, download_url=None)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["source_type"], "magnet")
        self.assertEqual(svc.last_create_kwargs["source_type"], "magnet")
        self.assertEqual(svc.last_create_kwargs["source_value"], _MAGNET)

    def test_magnet_preferred_when_both_present(self):
        """When both magnet_url and download_url exist, magnet is always used."""
        cache, result_id = _make_cache_with_result(magnet_url=_MAGNET, download_url=_DOWNLOAD_URL)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(svc.last_create_kwargs["source_type"], "magnet")
        # HTTP was never called — no requests.get
        self.assertNotIn(_DOWNLOAD_URL, str(svc.last_create_kwargs))


# ── Tests: download_url path (server-side fetch) ──────────────────────────────

class TestDownloadUrlPath(unittest.TestCase):

    def test_download_url_fetched_server_side_torrent_file_job(self):
        """download_url only → backend fetches torrent, creates torrent_file job."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", _mock_http_ok()):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["source_type"], "torrent_file")
        # create_torrent_file_job was called, not create_job
        self.assertIn("uploaded_path", svc.last_torrent_kwargs)
        # create_job should NOT have been called (last_create_kwargs stays empty)
        self.assertEqual(svc.last_create_kwargs, {})

    def test_download_url_never_passed_to_provider(self):
        """The Prowlarr download_url must never appear in the job service call."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", _mock_http_ok()):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        # Neither the URL nor its tokens must appear in any job service argument
        kwargs_str = str(svc.last_torrent_kwargs)
        self.assertNotIn("SECRETTOKEN", kwargs_str)
        self.assertNotIn("HIDDEN", kwargs_str)
        self.assertNotIn("apikey", kwargs_str)
        self.assertNotIn(_DOWNLOAD_URL, kwargs_str)

    def test_download_url_404_returns_502(self):
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        app = _make_app(cache=cache)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", _mock_http_status(404)):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_TORRENT_NOT_FOUND")

    def test_download_url_500_returns_502(self):
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        app = _make_app(cache=cache)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", _mock_http_status(500)):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_DOWNLOAD_FAILED")

    def test_download_url_invalid_content_returns_422(self):
        """Non-torrent content (e.g. HTML) returns PROWLARR_INVALID_TORRENT."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        app = _make_app(cache=cache)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get",
                   _mock_http_ok(b"<html>Not a torrent</html>")):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_INVALID_TORRENT")

    def test_download_url_timeout_returns_502(self):
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        app = _make_app(cache=cache)
        import requests as req_mod
        timeout_mock = MagicMock(side_effect=req_mod.Timeout("timed out"))
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", timeout_mock):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_DOWNLOAD_TIMEOUT")


# ── Tests: no URL ─────────────────────────────────────────────────────────────

class TestNoUrl(unittest.TestCase):

    def test_no_url_returns_prowlarr_no_url(self):
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=None)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_NO_URL")


# ── Tests: input validation ───────────────────────────────────────────────────

class TestValidation(unittest.TestCase):

    def test_missing_result_id_returns_400(self):
        app = _make_app(cache=ProwlarrResultCache(ttl_minutes=5))
        with app.test_client() as c:
            r = _post_jobs(c, {})
        self.assertEqual(r.status_code, 400)

    def test_empty_result_id_returns_400(self):
        app = _make_app(cache=ProwlarrResultCache(ttl_minutes=5))
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": "  "})
        self.assertEqual(r.status_code, 400)

    def test_expired_result_id_returns_404(self):
        app = _make_app(cache=ProwlarrResultCache(ttl_minutes=5))
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": "no-such-id"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_RESULT_NOT_FOUND")

    def test_cache_unavailable_returns_503(self):
        app = _make_app(cache=None)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": "any"})
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_CACHE_UNAVAILABLE")


# ── Tests: user isolation ─────────────────────────────────────────────────────

class TestUserIsolation(unittest.TestCase):

    def test_wrong_user_cannot_use_result(self):
        cache, result_id = _make_cache_with_result(user_id=_USER_ID)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id}, token=_OTHER_TOKEN)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json().get("code"), "PROWLARR_RESULT_NOT_FOUND")

    def test_correct_user_can_use_result(self):
        cache, result_id = _make_cache_with_result(user_id=_USER_ID)
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id}, token=_USER_TOKEN)
        self.assertEqual(r.status_code, 201)


# ── Tests: security ───────────────────────────────────────────────────────────

class TestSecurity(unittest.TestCase):

    def test_response_has_no_sensitive_fields(self):
        """Response body must not expose download_url, magnet_url, info_url, or tokens."""
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
        self.assertNotIn("apikey", raw)

    def test_response_fields_include_started(self):
        """Response must include id, status, source_type, started (and no sensitive fields)."""
        cache, result_id = _make_cache_with_result()
        app = _make_app(cache=cache)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        for field in ("id", "status", "source_type", "started"):
            self.assertIn(field, body)
        for field in ("download_url", "magnet_url", "info_url", "api_key", "apikey", "passkey"):
            self.assertNotIn(field, body)

    def test_download_url_tokens_not_in_response(self):
        """For the download_url path, the Prowlarr URL tokens must not leak."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        app = _make_app(cache=cache)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", _mock_http_ok()):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        raw = r.data.decode()
        self.assertNotIn("SECRETTOKEN", raw)
        self.assertNotIn("HIDDEN", raw)
        self.assertNotIn("apikey", raw)


# ── Tests: service errors ─────────────────────────────────────────────────────

class TestServiceErrors(unittest.TestCase):

    def test_provider_value_error_returns_400(self):
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService(raise_exc=ValueError("No active provider"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 400)
        self.assertIn("No active provider", r.get_json().get("error", ""))


# ── Tests: auto-start ─────────────────────────────────────────────────────────

class TestAutoStart(unittest.TestCase):

    def test_magnet_job_auto_started(self):
        """After magnet job creation, start_job is called and started=True."""
        cache, result_id = _make_cache_with_result(magnet_url=_MAGNET, download_url=None)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertTrue(body["started"])
        self.assertEqual(svc.last_start_job_id, "fake-job-001")

    def test_torrent_file_job_auto_started(self):
        """After torrent_file job creation, start_job is called and started=True."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", _mock_http_ok()):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertTrue(body["started"])
        self.assertIsNotNone(svc.last_start_job_id)

    def test_start_failure_returns_partial_success(self):
        """If start_job raises, job is preserved: 201, started=False, start_error set."""
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService(start_raise=ValueError("Provider rejected this link"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertFalse(body["started"])
        self.assertIn("id", body)
        self.assertIn("start_error", body)
        self.assertIn("Provider rejected", body["start_error"])

    def test_start_failure_no_secret_leak(self):
        """start_error must never contain the Prowlarr URL or embedded tokens."""
        cache, result_id = _make_cache_with_result(magnet_url=None, download_url=_DOWNLOAD_URL)
        svc = FakeJobService(start_raise=ValueError("Provider rejected"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c, \
             patch("backend.routes_v2.prowlarr_search.requests.get", _mock_http_ok()):
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        raw = r.data.decode()
        self.assertNotIn("SECRETTOKEN", raw)
        self.assertNotIn("HIDDEN", raw)
        self.assertNotIn("apikey", raw)
        self.assertNotIn(_DOWNLOAD_URL, raw)

    def test_start_failure_job_id_always_returned(self):
        """Even when start fails, the created job's id is always in the response."""
        cache, result_id = _make_cache_with_result()
        svc = FakeJobService(start_raise=RuntimeError("Provider factory not configured"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertIn("id", body)
        self.assertFalse(body["started"])

    def test_cached_title_stored_as_provider_payload_name(self):
        """After job creation, cached.title must be persisted in provider_payload_json
        so the Jobs page can show it instead of the raw magnet/download URL."""
        cache, result_id = _make_cache_with_result(title="Interstellar 2014")
        svc = FakeJobService()
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        svc.job_repository.update_provider_state.assert_called_once()
        called_job = svc.job_repository.update_provider_state.call_args[0][0]
        payload = json.loads(called_job.provider_payload_json or "{}")
        self.assertEqual(payload.get("name"), "Interstellar 2014")

    def test_cached_title_stored_even_when_start_fails(self):
        """Title is persisted even when auto-start raises — job stays visible."""
        cache, result_id = _make_cache_with_result(title="Dune Part Two")
        svc = FakeJobService(start_raise=ValueError("Provider rejected"))
        app = _make_app(cache=cache, job_service=svc)
        with app.test_client() as c:
            r = _post_jobs(c, {"result_id": result_id})
        self.assertEqual(r.status_code, 201)
        svc.job_repository.update_provider_state.assert_called_once()
        called_job = svc.job_repository.update_provider_state.call_args[0][0]
        payload = json.loads(called_job.provider_payload_json or "{}")
        self.assertEqual(payload.get("name"), "Dune Part Two")


if __name__ == "__main__":
    unittest.main(verbosity=2)
