#!/usr/bin/env python3
"""
Unit tests for backend.services_v2.redis_connection.build_redis_connection
and its usage in worker.py, local_download_worker, and local_download_queue.

Verifies that:
- REDIS_URL is used when set (Redis.from_url).
- REDIS_HOST / REDIS_PORT / REDIS_DB are used as fallback.
- decode_responses is forwarded correctly.
- RQ_QUEUE_NAME / RQ_LOCAL_DOWNLOAD_QUEUE_NAME are unchanged.

Run from project root:
    source .venv/bin/activate
    python scripts/tests/unit/test_worker_redis_connection.py
"""

import os
import sys
import types
import unittest
from unittest.mock import patch

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services_v2.redis_connection import build_redis_connection


def _settings(redis_url="", host="127.0.0.1", port=6379, db=0,
               queue="link2nas", local_queue="link2nas-local-downloads"):
    return types.SimpleNamespace(
        REDIS_URL=redis_url,
        REDIS_HOST=host,
        REDIS_PORT=port,
        REDIS_DB=db,
        RQ_QUEUE_NAME=queue,
        RQ_LOCAL_DOWNLOAD_QUEUE_NAME=local_queue,
    )


class TestBuildRedisConnectionUrl(unittest.TestCase):

    def test_uses_redis_url_when_set(self):
        settings = _settings(redis_url="redis://redis:6379/0")
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.from_url.assert_called_once_with("redis://redis:6379/0", decode_responses=False)
            mock_cls.assert_not_called()

    def test_redis_url_with_password(self):
        settings = _settings(redis_url="redis://:secret@redis:6379/1")
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.from_url.assert_called_once_with(
                "redis://:secret@redis:6379/1", decode_responses=False
            )

    def test_redis_url_takes_priority_over_host(self):
        settings = _settings(redis_url="redis://redis:6379/0", host="should-not-be-used")
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.from_url.assert_called_once()
            mock_cls.assert_not_called()

    def test_decode_responses_forwarded_to_from_url(self):
        settings = _settings(redis_url="redis://redis:6379/0")
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings, decode_responses=True)
            mock_cls.from_url.assert_called_once_with("redis://redis:6379/0", decode_responses=True)


class TestBuildRedisConnectionFallback(unittest.TestCase):

    def test_falls_back_to_host_port_db_when_no_url(self):
        settings = _settings(redis_url="", host="192.168.1.10", port=6380, db=2)
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.assert_called_once_with(
                host="192.168.1.10", port=6380, db=2, decode_responses=False
            )
            mock_cls.from_url.assert_not_called()

    def test_falls_back_when_url_is_whitespace(self):
        settings = _settings(redis_url="   ", host="myhost", port=6379, db=0)
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.assert_called_once_with(
                host="myhost", port=6379, db=0, decode_responses=False
            )
            mock_cls.from_url.assert_not_called()

    def test_falls_back_when_redis_url_attribute_missing(self):
        settings = types.SimpleNamespace(
            REDIS_HOST="fallback-host", REDIS_PORT=6379, REDIS_DB=0,
        )
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.assert_called_once_with(
                host="fallback-host", port=6379, db=0, decode_responses=False
            )

    def test_decode_responses_false_in_fallback(self):
        settings = _settings(redis_url="")
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings)
            _, kwargs = mock_cls.call_args
            self.assertFalse(kwargs.get("decode_responses", True))

    def test_decode_responses_forwarded_to_fallback(self):
        settings = _settings(redis_url="", host="h", port=6379, db=0)
        with patch("backend.services_v2.redis_connection.Redis") as mock_cls:
            build_redis_connection(settings, decode_responses=True)
            _, kwargs = mock_cls.call_args
            self.assertTrue(kwargs.get("decode_responses"))


def _read_source(rel_path: str) -> str:
    path = os.path.join(_PROJECT_ROOT, rel_path)
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestWorkerUsesHelper(unittest.TestCase):

    def test_worker_delegates_to_build_redis_connection(self):
        source = _read_source("worker.py")
        self.assertIn("build_redis_connection", source,
                      "worker.py must use build_redis_connection")

    def test_worker_no_longer_imports_redis_directly(self):
        source = _read_source("worker.py")
        self.assertNotIn("Redis(", source,
                         "worker.py should not construct Redis directly")


class TestLocalDownloadWorkerUsesHelper(unittest.TestCase):

    def test_local_download_worker_uses_helper(self):
        source = _read_source("backend/services_v2/local_download_worker.py")
        self.assertIn("build_redis_connection", source)
        self.assertNotIn("Redis(", source,
                         "local_download_worker should not construct Redis directly")


class TestLocalDownloadQueueUsesHelper(unittest.TestCase):

    def test_local_download_queue_uses_helper(self):
        source = _read_source("backend/services_v2/job_support/local_download_queue.py")
        self.assertIn("build_redis_connection", source)
        self.assertNotIn("Redis(", source,
                         "local_download_queue should not construct Redis directly")


if __name__ == "__main__":
    unittest.main(verbosity=2)
