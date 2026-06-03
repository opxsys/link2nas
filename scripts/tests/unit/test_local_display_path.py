#!/usr/bin/env python3
"""
Unit tests for _local_display_path in job serialization.

Verifies that local destination paths are sanitized for API exposure:
- internal absolute prefix is stripped
- user_id is not present in the result
- destination_path (the original field) is never mutated
- Synology/NAS paths pass through unchanged

Run from project root:
    python -m unittest scripts.tests.unit.test_local_display_path
    python scripts/tests/unit/test_local_display_path.py
"""
import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.routes_v2.jobs_support.display_path import local_display_path as _local_display_path  # noqa: E402

USER_ID = "f2e1d498-c527-471d-ba12-90816881fa78"
USERDATA_DIR = "/app/data/userdata"
INTERNAL_PATH = f"/app/data/userdata/{USER_ID}/local/sqdfdr/The.Punisher.mp4"


class TestLocalDisplayPathStripping(unittest.TestCase):

    def _call(self, path, dest_name="local", dest_type="local"):
        return _local_display_path(path, dest_name, dest_type, USER_ID, USERDATA_DIR)

    def test_returns_relative_suffix(self):
        result = self._call(INTERNAL_PATH)
        self.assertEqual(result, "sqdfdr/The.Punisher.mp4")

    def test_no_userdata_in_result(self):
        result = self._call(INTERNAL_PATH)
        self.assertNotIn("userdata", result)

    def test_no_user_id_in_result(self):
        result = self._call(INTERNAL_PATH)
        self.assertNotIn(USER_ID, result)

    def test_no_app_prefix_in_result(self):
        result = self._call(INTERNAL_PATH)
        self.assertFalse(result.startswith("/"), f"result must be relative, got: {result}")

    def test_destination_path_field_not_mutated(self):
        # Simulates: serialize returns both destination_path and destination_display_path
        original = INTERNAL_PATH
        display = self._call(original)
        self.assertEqual(original, INTERNAL_PATH, "original path must not be mutated")
        self.assertNotEqual(display, original)

    def test_detected_by_destination_name(self):
        result = _local_display_path(INTERNAL_PATH, "local", None, USER_ID, USERDATA_DIR)
        self.assertEqual(result, "sqdfdr/The.Punisher.mp4")

    def test_detected_by_destination_type(self):
        result = _local_display_path(INTERNAL_PATH, None, "local", USER_ID, USERDATA_DIR)
        self.assertEqual(result, "sqdfdr/The.Punisher.mp4")

    def test_nested_path(self):
        path = f"/app/data/userdata/{USER_ID}/local/folder/sub/file.mkv"
        result = self._call(path)
        self.assertEqual(result, "folder/sub/file.mkv")

    def test_flat_filename(self):
        path = f"/app/data/userdata/{USER_ID}/local/video.mp4"
        result = self._call(path)
        self.assertEqual(result, "video.mp4")

    def test_configurable_userdata_dir(self):
        path = "/mnt/storage/userdata/abc123/local/myfolder/vid.mkv"
        result = _local_display_path(path, "local", "local", "abc123", "/mnt/storage/userdata")
        self.assertEqual(result, "myfolder/vid.mkv")
        self.assertNotIn("abc123", result)


class TestLocalDisplayPathNonLocal(unittest.TestCase):

    def test_synology_path_unchanged(self):
        path = "/volume1/downloads/file.mp4"
        result = _local_display_path(path, "synology", "synology", USER_ID, USERDATA_DIR)
        self.assertEqual(result, path)

    def test_nas_path_unchanged(self):
        path = "/volume1/media/series/s01e01.mkv"
        result = _local_display_path(path, "nas", "synology", USER_ID, USERDATA_DIR)
        self.assertEqual(result, path)

    def test_none_destination_name_and_type_unchanged(self):
        path = "/some/path/file.mp4"
        result = _local_display_path(path, None, None, USER_ID, USERDATA_DIR)
        self.assertEqual(result, path)


class TestLocalDisplayPathDefensive(unittest.TestCase):

    def test_none_path_returns_none(self):
        result = _local_display_path(None, "local", "local", USER_ID, USERDATA_DIR)
        self.assertIsNone(result)

    def test_empty_path_returns_none(self):
        result = _local_display_path("", "local", "local", USER_ID, USERDATA_DIR)
        self.assertIsNone(result)

    def test_unrecognized_prefix_falls_back(self):
        path = "/some/other/path/file.mp4"
        result = _local_display_path(path, "local", "local", USER_ID, USERDATA_DIR)
        self.assertEqual(result, path)

    def test_missing_user_id_falls_back(self):
        result = _local_display_path(INTERNAL_PATH, "local", "local", None, USERDATA_DIR)
        self.assertEqual(result, INTERNAL_PATH)

    def test_missing_userdata_dir_falls_back(self):
        result = _local_display_path(INTERNAL_PATH, "local", "local", USER_ID, None)
        self.assertEqual(result, INTERNAL_PATH)

    def test_wrong_user_id_falls_back(self):
        result = _local_display_path(INTERNAL_PATH, "local", "local", "other-user-id", USERDATA_DIR)
        self.assertEqual(result, INTERNAL_PATH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
