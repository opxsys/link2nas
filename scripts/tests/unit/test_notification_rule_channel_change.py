#!/usr/bin/env python3
"""
Unit tests validating that updating a notification rule's config_id causes
subsequent events to dispatch to the new channel, not the old one.

Scenario: rule created with config A (email) → updated to config B (gotify)
→ new event created → event dispatched to B, not A.

Run from project root:
    source .venv/bin/activate
    python scripts/tests/unit/test_notification_rule_channel_change.py
"""

import json
import os
import sys
import unittest
import uuid

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.notification_config import NotificationConfig
from backend.models.notification_rule import NotificationRule
from backend.services_v2.notification_support.events import create_event_impl
from backend.services_v2.notification_support.rule_matching import match_rules_impl
from backend.services_v2.notification_support.rules import update_rule_impl
from backend.services_v2.notification_support.serialization import rule_to_public_dict
from backend.services_v2.notification_support.validation import (
    validate_event_types,
    validate_rate_limit,
    validate_scope,
    validate_severity,
)


USER_ID = "user-test-1"
NOW = "2026-06-08T00:00:00Z"


def _make_config(cid: str, channel: str, enabled: bool = True) -> NotificationConfig:
    return NotificationConfig(
        id=cid,
        user_id=USER_ID,
        name=f"Config {channel}",
        channel=channel,
        is_enabled=enabled,
        is_default=False,
        config_json="{}",
        created_at=NOW,
        updated_at=NOW,
    )


def _make_rule(rule_id: str, config_id: str) -> NotificationRule:
    return NotificationRule(
        id=rule_id,
        user_id=USER_ID,
        name="Test rule",
        scope="user",
        is_enabled=True,
        config_id=config_id,
        severity_min="info",
        event_types_json="[]",
        rate_limit_per_hour=30,
        created_at=NOW,
        updated_at=NOW,
    )


class InMemoryConfigRepo:
    def __init__(self, configs):
        self._configs = {c.id: c for c in configs}

    def get_by_id(self, user_id, config_id):
        return self._configs.get(config_id)


class InMemoryRuleRepo:
    def __init__(self, rules):
        self._rules = {r.id: r for r in rules}

    def get_by_id(self, user_id, rule_id):
        return self._rules.get(rule_id)

    def list_for_user(self, user_id):
        return [r for r in self._rules.values() if r.user_id == user_id]

    def list_enabled_for_user(self, user_id, scope=None):
        return [
            r for r in self._rules.values()
            if r.user_id == user_id and r.is_enabled
            and (scope is None or r.scope == scope)
        ]

    def create(self, rule):
        self._rules[rule.id] = rule
        return rule

    def update(self, rule):
        self._rules[rule.id] = rule
        return rule


class InMemoryEventRepo:
    def __init__(self):
        self._events = {}

    def create(self, event):
        self._events[event.id] = event
        return event

    def get_all(self):
        return list(self._events.values())


class TestNotificationRuleChannelChange(unittest.TestCase):

    def setUp(self):
        self.config_a = _make_config("config-email", "email")
        self.config_b = _make_config("config-gotify", "gotify")
        self.config_repo = InMemoryConfigRepo([self.config_a, self.config_b])

        self.rule_id = "rule-1"
        initial_rule = _make_rule(self.rule_id, "config-email")
        self.rule_repo = InMemoryRuleRepo([initial_rule])
        self.event_repo = InMemoryEventRepo()

    def _match_rules(self, user_id, event_type, severity, scope):
        return match_rules_impl(
            self.rule_repo,
            self.config_repo,
            lambda s: {"info": 0, "warning": 1, "error": 2, "critical": 3}.get(s, 0),
            user_id,
            event_type,
            severity,
            scope,
        )

    def _create_event(self):
        return create_event_impl(
            self.event_repo,
            self._match_rules,
            lambda e: {"id": e.id, "triggered_by_config_ids": json.loads(e.triggered_by_config_ids_json or "[]")},
            lambda v, name: str(v),
            lambda v: v,
            lambda v: v,
            USER_ID,
            type="job.completed",
            severity="info",
            title="Job done",
            message="Test message",
            scope="user",
        )

    def test_event_uses_initial_config(self):
        result = self._create_event()
        self.assertIn("config-email", result["triggered_by_config_ids"])
        self.assertNotIn("config-gotify", result["triggered_by_config_ids"])

    def test_event_uses_new_config_after_rule_update(self):
        update_rule_impl(
            self.config_repo,
            self.rule_repo,
            lambda v, name: str(v),
            validate_scope,
            validate_severity,
            validate_event_types,
            validate_rate_limit,
            rule_to_public_dict,
            RuntimeError,
            USER_ID,
            self.rule_id,
            {"config_id": "config-gotify", "name": "Test rule", "is_enabled": True},
        )

        result = self._create_event()
        self.assertNotIn("config-email", result["triggered_by_config_ids"],
                         "Old channel (email) should NOT be in the event after rule update")
        self.assertIn("config-gotify", result["triggered_by_config_ids"],
                      "New channel (gotify) MUST be in the event after rule update")

    def test_rule_update_persists_new_config_id(self):
        updated = update_rule_impl(
            self.config_repo,
            self.rule_repo,
            lambda v, name: str(v),
            validate_scope,
            validate_severity,
            validate_event_types,
            validate_rate_limit,
            rule_to_public_dict,
            RuntimeError,
            USER_ID,
            self.rule_id,
            {"config_id": "config-gotify", "name": "Test rule", "is_enabled": True},
        )
        self.assertEqual(updated["config_id"], "config-gotify")
        persisted = self.rule_repo.get_by_id(USER_ID, self.rule_id)
        self.assertEqual(persisted.config_id, "config-gotify")

    def test_disabled_config_not_matched(self):
        disabled_config = _make_config("config-disabled", "webhook", enabled=False)
        self.config_repo._configs["config-disabled"] = disabled_config
        rule = _make_rule("rule-disabled", "config-disabled")
        self.rule_repo.update(rule)

        matched = self._match_rules(USER_ID, "job.completed", "info", "user")
        matched_ids = [r.config_id for r in matched]
        self.assertNotIn("config-disabled", matched_ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
