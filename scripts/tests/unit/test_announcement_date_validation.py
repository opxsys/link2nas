#!/usr/bin/env python3
"""
Unit tests for validate_announcement_dates / _parse_iso.

Run from project root:
    source .venv/bin/activate
    python scripts/tests/unit/test_announcement_date_validation.py
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services_v2.announcement_support.validation import (
    _parse_iso,
    validate_announcement_dates,
)

_NOW = datetime.now(timezone.utc)
_PAST = _NOW - timedelta(days=1)
_FUTURE_1H = _NOW + timedelta(hours=1)
_FUTURE_24H = _NOW + timedelta(hours=24)
_FUTURE_48H = _NOW + timedelta(hours=48)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class TestParseIso(unittest.TestCase):
    def test_parses_with_utc_offset(self):
        dt = _parse_iso("2026-06-05T10:00:00+00:00")
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_parses_with_z_suffix(self):
        dt = _parse_iso("2026-06-05T10:00:00Z")
        self.assertIsNotNone(dt.tzinfo)

    def test_naive_string_assumed_utc(self):
        dt = _parse_iso("2026-06-05T10:00:00")
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_raises_on_bad_format(self):
        with self.assertRaises(ValueError):
            _parse_iso("not-a-date")

    def test_raises_on_empty_string(self):
        with self.assertRaises(ValueError):
            _parse_iso("")


class TestValidateAnnouncementDates(unittest.TestCase):

    # --- OK cases ---

    def test_both_absent_ok(self):
        validate_announcement_dates({})
        validate_announcement_dates({"starts_at": None, "ends_at": None})
        validate_announcement_dates({"starts_at": "", "ends_at": ""})

    def test_only_starts_at_future_ok(self):
        validate_announcement_dates({"starts_at": _iso(_FUTURE_24H), "is_active": True})

    def test_starts_now_ends_tomorrow_active_ok(self):
        validate_announcement_dates({
            "starts_at": _iso(_NOW),
            "ends_at": _iso(_FUTURE_24H),
            "is_active": True,
        })

    def test_starts_tomorrow_ends_day_after_ok(self):
        validate_announcement_dates({
            "starts_at": _iso(_FUTURE_24H),
            "ends_at": _iso(_FUTURE_48H),
            "is_active": True,
        })

    def test_inactive_past_dates_ok(self):
        # Archived/historical announcements — is_active=False skips past ends_at check
        validate_announcement_dates({
            "starts_at": _iso(_PAST - timedelta(days=1)),
            "ends_at": _iso(_PAST),
            "is_active": False,
        })

    def test_only_ends_at_future_active_ok(self):
        validate_announcement_dates({"ends_at": _iso(_FUTURE_24H), "is_active": True})

    def test_update_no_date_fields_ok(self):
        class FakeAnn:
            starts_at = _iso(_PAST)
            ends_at = None
            is_active = True

        validate_announcement_dates({"title": "Updated title"}, existing=FakeAnn())

    def test_update_deactivate_keeps_past_ends_ok(self):
        # Flipping is_active=False on an expired announcement should be allowed.
        class FakeAnn:
            starts_at = None
            ends_at = _iso(_PAST)
            is_active = True

        validate_announcement_dates({"is_active": False}, existing=FakeAnn())

    # --- Error cases ---

    def test_ends_before_starts_error(self):
        with self.assertRaises(ValueError) as cm:
            validate_announcement_dates({
                "starts_at": _iso(_FUTURE_48H),
                "ends_at": _iso(_FUTURE_24H),
                "is_active": True,
            })
        self.assertIn("End date must be after start date", str(cm.exception))

    def test_ends_equal_starts_error(self):
        ts = _iso(_FUTURE_24H)
        with self.assertRaises(ValueError) as cm:
            validate_announcement_dates({"starts_at": ts, "ends_at": ts, "is_active": True})
        self.assertIn("End date must be after start date", str(cm.exception))

    def test_active_ends_in_past_error(self):
        with self.assertRaises(ValueError) as cm:
            validate_announcement_dates({"ends_at": _iso(_PAST), "is_active": True})
        self.assertIn("End date must be in the future", str(cm.exception))

    def test_active_ends_in_past_no_is_active_key_defaults_true_error(self):
        # When is_active is absent, defaults to True
        with self.assertRaises(ValueError):
            validate_announcement_dates({"ends_at": _iso(_PAST)})

    def test_update_existing_active_new_past_ends_error(self):
        class FakeAnn:
            starts_at = None
            ends_at = _iso(_FUTURE_24H)
            is_active = True

        with self.assertRaises(ValueError):
            validate_announcement_dates({"ends_at": _iso(_PAST)}, existing=FakeAnn())

    def test_update_existing_swaps_starts_ends_error(self):
        class FakeAnn:
            starts_at = _iso(_FUTURE_24H)
            ends_at = _iso(_FUTURE_48H)
            is_active = True

        with self.assertRaises(ValueError) as cm:
            # New ends_at placed before existing starts_at
            validate_announcement_dates({"ends_at": _iso(_FUTURE_1H)}, existing=FakeAnn())
        self.assertIn("End date must be after start date", str(cm.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
