#!/usr/bin/env python3
"""
Unit tests for worker.build_redis_connection.

Verifies that:
- REDIS_URL is used when set (Redis.from_url).
- REDIS_HOST / REDIS_PORT / REDIS_DB are used as fallback.
- decode_responses=False in both cases.
- RQ_QUEUE_NAME is unchanged.

Run from project root:
    source .venv/bin/activate
    python scripts/tests/unit/test_worker_redis_connection.py
"""

import os
import sys
import types
import unittest
from unittest.mock import patch, MagicMock, call

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from worker import build_redis_connection


def _settings(redis_url="", host="127.0.0.1", port=6379, db=0, queue="link2nas"):
    s = types.SimpleNamespace(
        REDIS_URL=redis_url,
        REDIS_HOST=host,
        REDIS_PORT=port,
        REDIS_DB=db,
        RQ_QUEUE_NAME=queue,
    )
    return s


class TestBuildRedisConnectionUrl(unittest.TestCase):

    def test_uses_redis_url_when_set(self):
        settings = _settings(redis_url="redis://redis:6379/0")
        with patch("worker.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.from_url.assert_called_once_with("redis://redis:6379/0", decode_responses=False)
            mock_cls.assert_not_called()

    def test_redis_url_with_password(self):
        settings = _settings(redis_url="redis://:secret@redis:6379/1")
        with patch("worker.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.from_url.assert_called_once_with(
                "redis://:secret@redis:6379/1", decode_responses=False
            )

    def test_redis_url_takes_priority_over_host(self):
        settings = _settings(redis_url="redis://redis:6379/0", host="should-not-be-used")
        with patch("worker.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.from_url.assert_called_once()
            mock_cls.assert_not_called()


class TestBuildRedisConnectionFallback(unittest.TestCase):

    def test_falls_back_to_host_port_db_when_no_url(self):
        settings = _settings(redis_url="", host="192.168.1.10", port=6380, db=2)
        with patch("worker.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.assert_called_once_with(
                host="192.168.1.10", port=6380, db=2, decode_responses=False
            )
            mock_cls.from_url.assert_not_called()

    def test_falls_back_when_url_is_whitespace(self):
        settings = _settings(redis_url="   ", host="myhost", port=6379, db=0)
        with patch("worker.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.assert_called_once_with(
                host="myhost", port=6379, db=0, decode_responses=False
            )
            mock_cls.from_url.assert_not_called()

    def test_falls_back_when_redis_url_attribute_missing(self):
        settings = types.SimpleNamespace(
            REDIS_HOST="fallback-host",
            REDIS_PORT=6379,
            REDIS_DB=0,
            RQ_QUEUE_NAME="link2nas",
        )
        with patch("worker.Redis") as mock_cls:
            build_redis_connection(settings)
            mock_cls.assert_called_once_with(
                host="fallback-host", port=6379, db=0, decode_responses=False
            )

    def test_decode_responses_false_in_fallback(self):
        settings = _settings(redis_url="")
        with patch("worker.Redis") as mock_cls:
            build_redis_connection(settings)
            _, kwargs = mock_cls.call_args
            self.assertFalse(kwargs.get("decode_responses", True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
