#!/usr/bin/env python3
"""
Unit tests for destination_registry.

Run from project root:
    python scripts/tests/unit/test_destination_registry.py
"""

import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services_v2.destination_registry import (
    DESTINATION_ALIAS_KEYS,
    DESTINATION_ALL_KEYS,
    DESTINATION_DISPLAY_NAMES,
    DESTINATION_KEYS,
)


class TestDestinationKeys(unittest.TestCase):
    def test_canonical_keys(self):
        self.assertIn("synology", DESTINATION_KEYS)
        self.assertIn("local", DESTINATION_KEYS)

    def test_canonical_keys_is_frozenset(self):
        self.assertIsInstance(DESTINATION_KEYS, frozenset)

    def test_alias_keys(self):
        self.assertIn("nas", DESTINATION_ALIAS_KEYS)
        self.assertEqual(DESTINATION_ALIAS_KEYS["nas"], "synology")

    def test_all_keys_includes_canonical_and_aliases(self):
        for key in DESTINATION_KEYS:
            self.assertIn(key, DESTINATION_ALL_KEYS)
        for alias in DESTINATION_ALIAS_KEYS:
            self.assertIn(alias, DESTINATION_ALL_KEYS)

    def test_all_keys_is_frozenset(self):
        self.assertIsInstance(DESTINATION_ALL_KEYS, frozenset)

    def test_display_names_cover_all_canonical_keys(self):
        for key in DESTINATION_KEYS:
            self.assertIn(key, DESTINATION_DISPLAY_NAMES, f"Missing display name for {key}")

    def test_display_names_are_non_empty_strings(self):
        for key, name in DESTINATION_DISPLAY_NAMES.items():
            self.assertIsInstance(name, str)
            self.assertTrue(name.strip(), f"Empty display name for {key}")

    def test_aliases_resolve_to_canonical_keys(self):
        for alias, canonical in DESTINATION_ALIAS_KEYS.items():
            self.assertIn(canonical, DESTINATION_KEYS, f"Alias {alias!r} → {canonical!r} not in DESTINATION_KEYS")

    def test_links_only_not_in_keys(self):
        # links_only is a pseudo-destination handled at routing level, not a real config type
        self.assertNotIn("links_only", DESTINATION_KEYS)
        self.assertNotIn("links_only", DESTINATION_ALL_KEYS)


if __name__ == "__main__":
    unittest.main()
