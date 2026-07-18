#!/usr/bin/env python3
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask, jsonify

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.repositories.sqlite.app_settings_repository import AppSettingsRepository
from backend.routes_v2.admin_app_settings import admin_app_settings_bp
from backend.services_v2.app_settings_service import AppSettingsService, AppSettingsValidationError
from backend.services_v2.notification_dispatcher_service import NotificationDispatcherService
from backend.storage.db import Database


class AdminNotificationSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "settings.sqlite3"))
        self.db.init_schema(os.path.join(_PROJECT_ROOT, "backend/storage/schema.sql"))
        self.service = AppSettingsService(
            AppSettingsRepository(self.db),
            notification_event_max_age_hours=36,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_environment_value_is_fallback_until_setting_is_saved(self):
        self.assertEqual({"max_age_hours": 36}, self.service.get_notification_event_policy())
        self.assertIsNone(self.service.repository.get("notifications.event_policy"))
        self.service.save_notification_event_policy({"max_age_hours": 48})
        self.assertEqual({"max_age_hours": 48}, self.service.get_notification_event_policy())

    def test_bounds_are_enforced(self):
        for value in (0, 721):
            with self.subTest(value=value), self.assertRaises(AppSettingsValidationError):
                self.service.save_notification_event_policy({"max_age_hours": value})
        self.assertEqual(1, self.service.save_notification_event_policy({"max_age_hours": 1})["max_age_hours"])
        self.assertEqual(720, self.service.save_notification_event_policy({"max_age_hours": 720})["max_age_hours"])

    def test_dispatcher_reads_changed_value_without_restart(self):
        dispatcher = NotificationDispatcherService(
            None, None, None, None, app_settings_service=self.service, max_age_hours=24
        )
        self.assertEqual(36, dispatcher._effective_max_age_hours())
        self.service.save_notification_event_policy({"max_age_hours": 72})
        self.assertEqual(72, dispatcher._effective_max_age_hours())

    def test_secure_get_and_put_api(self):
        app = Flask(__name__)
        app.config["APP_SETTINGS_SERVICE_V2"] = self.service
        app.register_blueprint(admin_app_settings_bp)
        client = app.test_client()

        with patch(
            "backend.routes_v2.admin_app_settings.require_super_admin",
            return_value=(object(), None),
        ):
            response = client.get("/api/v2/admin/app-settings/notifications")
            self.assertEqual(200, response.status_code)
            self.assertEqual(36, response.get_json()["event_policy"]["max_age_hours"])
            response = client.put(
                "/api/v2/admin/app-settings/notifications",
                json={"event_policy": {"max_age_hours": 12}},
            )
            self.assertEqual(200, response.status_code)
            self.assertEqual(12, response.get_json()["event_policy"]["max_age_hours"])
            invalid = client.put(
                "/api/v2/admin/app-settings/notifications",
                json={"event_policy": {"max_age_hours": 900}},
            )
            self.assertEqual(400, invalid.status_code)

        def forbidden():
            return None, (jsonify({"error": "Super admin required"}), 403)

        with patch(
            "backend.routes_v2.admin_app_settings.require_super_admin",
            side_effect=forbidden,
        ):
            self.assertEqual(
                403,
                client.get("/api/v2/admin/app-settings/notifications").status_code,
            )

    def test_frontend_notification_admin_contract(self):
        component = (
            Path(_PROJECT_ROOT) / "frontend-next/src/pages/Admin/AdminNotifications.tsx"
        ).read_text(encoding="utf-8")
        api = (
            Path(_PROJECT_ROOT) / "frontend-next/src/api/admin-notification-settings.ts"
        ).read_text(encoding="utf-8")
        self.assertIn('type="number"', component)
        self.assertIn("min={1}", component)
        self.assertIn("max={720}", component)
        self.assertIn("DEFAULT_MAX_AGE_HOURS = 24", component)
        self.assertIn("adminNotificationMaxAgeHelp", component)
        self.assertIn("/api/v2/admin/app-settings/notifications", api)
        self.assertIn("method: 'PUT'", api)


if __name__ == "__main__":
    unittest.main(verbosity=2)
