#!/usr/bin/env python3
"""
Unit tests for provider_registry.

Run from project root:
    python scripts/tests/unit/test_provider_registry.py
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services_v2.provider_registry import (
    PROVIDER_DISPLAY_NAMES,
    PROVIDER_KEYS,
    build_provider,
)
from backend.services_v2.providers.alldebrid_provider import AllDebridProvider
from backend.services_v2.providers.realdebrid_provider import RealDebridProvider


class TestProviderKeys(unittest.TestCase):
    def test_contains_expected_types(self):
        self.assertIn("realdebrid", PROVIDER_KEYS)
        self.assertIn("alldebrid", PROVIDER_KEYS)

    def test_is_frozenset(self):
        self.assertIsInstance(PROVIDER_KEYS, frozenset)

    def test_display_names_cover_all_keys(self):
        for key in PROVIDER_KEYS:
            self.assertIn(key, PROVIDER_DISPLAY_NAMES, f"Missing display name for {key}")

    def test_display_names_are_strings(self):
        for key, name in PROVIDER_DISPLAY_NAMES.items():
            self.assertIsInstance(name, str)
            self.assertTrue(name.strip(), f"Empty display name for {key}")


class TestBuildProvider(unittest.TestCase):
    def _settings(self):
        s = MagicMock()
        s.REALDEBRID_BASE_URL = "https://api.real-debrid.com/rest/1.0"
        s.REALDEBRID_TIMEOUT = 30.0
        s.ALLDEBRID_BASE_URL = "https://api.alldebrid.com"
        s.ALLDEBRID_TIMEOUT = 30.0
        return s

    def test_realdebrid_returns_correct_type(self):
        provider = build_provider("realdebrid", "token_rd", self._settings())
        self.assertIsInstance(provider, RealDebridProvider)

    def test_alldebrid_returns_correct_type(self):
        provider = build_provider("alldebrid", "token_ad", self._settings())
        self.assertIsInstance(provider, AllDebridProvider)

    def test_unknown_type_raises_value_error(self):
        with self.assertRaises(ValueError):
            build_provider("unknown_provider", "token", self._settings())

    def test_empty_type_raises_value_error(self):
        with self.assertRaises(ValueError):
            build_provider("", "token", self._settings())


if __name__ == "__main__":
    unittest.main()
