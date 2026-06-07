#!/usr/bin/env python3
"""
Unit tests: IdentityProxyConfigService.

Covers:
  1.  create happy path Cloudflare Access
  2.  provider_type inconnu refusé
  3.  config_json invalide refusé (non-JSON)
  4.  config_json objet invalide (tableau)
  5.  config_json manque team_domain
  6.  config_json manque audience
  7.  allowed_domains_json invalide refusé
  8.  allowed_domains_json non-array refusé
  9.  allowed_domains_json array de non-strings refusé
  10. team_domain normalisé (https://, trailing slash)
  11. label par défaut si absent
  12. update conserve les champs non modifiés
  13. to_admin_dict inclut tous les champs attendus
  14. to_admin_dict n'expose pas de token / secret
  15. get_public_status: aucune config → disabled
  16. get_public_status: config disabled → disabled
  17. get_public_status: config enabled → champs publics
  18. delete lève erreur si id inconnu

Run from project root:
    python3 scripts/tests/unit/test_identity_proxy_config_service.py
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.services_v2.identity_proxy_config_service import IdentityProxyConfigService
from backend.services_v2.identity_proxy_validators.base import IdentityProxyConfigError


def _make_repo(existing: IdentityProxyConfig | None = None):
    repo = MagicMock()
    repo.get_by_id.return_value = existing
    repo.get_first.return_value = existing
    repo.list_all.return_value = [existing] if existing else []
    return repo


def _make_service(existing=None):
    return IdentityProxyConfigService(_make_repo(existing))


def _cf_config_json(**overrides) -> str:
    base = {"team_domain": "leang.cloudflareaccess.com", "audience": "test-aud"}
    base.update(overrides)
    return json.dumps(base)


class TestCreateConfig(unittest.TestCase):

    # ── 1. happy path ─────────────────────────────────────────────────────────

    def test_create_cloudflare_access_happy_path(self):
        svc = _make_service()
        cfg = svc.create_config(
            name="CF Access",
            provider_type="cloudflare_access",
            config_json=_cf_config_json(),
        )
        self.assertEqual(cfg.provider_type, "cloudflare_access")
        self.assertEqual(cfg.name, "CF Access")
        self.assertIsNotNone(cfg.id)
        self.assertIsNotNone(cfg.created_at)
        svc._repo.create.assert_called_once()

    # ── 2. provider_type inconnu ──────────────────────────────────────────────

    def test_unknown_provider_type_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="Bad", provider_type="unknown_provider", config_json="{}"
            )

    # ── 3. config_json non-JSON ────────────────────────────────────────────────

    def test_config_json_invalid_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="CF", provider_type="cloudflare_access", config_json="not-json"
            )

    # ── 4. config_json tableau refusé ─────────────────────────────────────────

    def test_config_json_array_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="CF", provider_type="cloudflare_access", config_json='["a", "b"]'
            )

    # ── 5. team_domain manquant ───────────────────────────────────────────────

    def test_missing_team_domain_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="CF",
                provider_type="cloudflare_access",
                config_json=json.dumps({"audience": "abc"}),
            )

    # ── 6. audience manquante ─────────────────────────────────────────────────

    def test_missing_audience_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="CF",
                provider_type="cloudflare_access",
                config_json=json.dumps({"team_domain": "leang.cloudflareaccess.com"}),
            )

    # ── 7. allowed_domains_json invalide ──────────────────────────────────────

    def test_allowed_domains_json_invalid_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="CF",
                provider_type="cloudflare_access",
                config_json=_cf_config_json(),
                allowed_domains_json="not-json",
            )

    # ── 8. allowed_domains_json non-array ─────────────────────────────────────

    def test_allowed_domains_json_non_array_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="CF",
                provider_type="cloudflare_access",
                config_json=_cf_config_json(),
                allowed_domains_json='{"a": 1}',
            )

    # ── 9. allowed_domains_json array de non-strings ──────────────────────────

    def test_allowed_domains_json_non_string_items_raises(self):
        svc = _make_service()
        with self.assertRaises(IdentityProxyConfigError):
            svc.create_config(
                name="CF",
                provider_type="cloudflare_access",
                config_json=_cf_config_json(),
                allowed_domains_json="[1, 2]",
            )

    # ── 10. team_domain normalisé ─────────────────────────────────────────────

    def test_team_domain_normalized_https(self):
        svc = _make_service()
        cfg = svc.create_config(
            name="CF",
            provider_type="cloudflare_access",
            config_json=json.dumps(
                {"team_domain": "https://leang.cloudflareaccess.com/", "audience": "x"}
            ),
        )
        stored = json.loads(cfg.config_json)
        self.assertEqual(stored["team_domain"], "leang.cloudflareaccess.com")

    def test_team_domain_normalized_http(self):
        svc = _make_service()
        cfg = svc.create_config(
            name="CF",
            provider_type="cloudflare_access",
            config_json=json.dumps(
                {"team_domain": "http://leang.cloudflareaccess.com", "audience": "x"}
            ),
        )
        stored = json.loads(cfg.config_json)
        self.assertEqual(stored["team_domain"], "leang.cloudflareaccess.com")

    # ── 11. label par défaut ──────────────────────────────────────────────────

    def test_default_label_cloudflare_access(self):
        svc = _make_service()
        cfg = svc.create_config(
            name="CF", provider_type="cloudflare_access", config_json=_cf_config_json()
        )
        self.assertEqual(cfg.label, "Continue with Cloudflare Access")

    def test_custom_label_preserved(self):
        svc = _make_service()
        cfg = svc.create_config(
            name="CF",
            provider_type="cloudflare_access",
            label="Login via CF",
            config_json=_cf_config_json(),
        )
        self.assertEqual(cfg.label, "Login via CF")


class TestUpdateConfig(unittest.TestCase):

    def _existing(self) -> IdentityProxyConfig:
        return IdentityProxyConfig(
            id="cfg-1",
            name="Original",
            provider_type="cloudflare_access",
            enabled=False,
            label="Continue with Cloudflare Access",
            auto_login=False,
            auto_create_users=False,
            allowed_domains_json="[]",
            config_json=_cf_config_json(),
            created_at="2026-01-01T00:00:00",
            updated_at="2026-01-01T00:00:00",
        )

    # ── 12. update conserve les champs non modifiés ───────────────────────────

    def test_update_preserves_unmodified_fields(self):
        existing = self._existing()
        svc = _make_service(existing)
        updated = svc.update_config("cfg-1", name="New Name")
        self.assertEqual(updated.name, "New Name")
        self.assertEqual(updated.provider_type, "cloudflare_access")
        self.assertEqual(updated.label, "Continue with Cloudflare Access")
        self.assertFalse(updated.enabled)

    def test_update_enabled_flag(self):
        existing = self._existing()
        svc = _make_service(existing)
        updated = svc.update_config("cfg-1", enabled=True)
        self.assertTrue(updated.enabled)

    def test_update_auto_create_users(self):
        existing = self._existing()
        svc = _make_service(existing)
        updated = svc.update_config("cfg-1", auto_create_users=True)
        self.assertTrue(updated.auto_create_users)


class TestAdminDict(unittest.TestCase):

    # ── 13 & 14. to_admin_dict ────────────────────────────────────────────────

    def test_to_admin_dict_fields(self):
        config = IdentityProxyConfig(
            id="cfg-1",
            name="CF Access",
            provider_type="cloudflare_access",
            enabled=True,
            label="Continue with Cloudflare Access",
            auto_login=False,
            auto_create_users=True,
            allowed_domains_json='["example.com"]',
            config_json=_cf_config_json(),
            created_at="2026-01-01T00:00:00",
            updated_at="2026-01-02T00:00:00",
        )
        svc = _make_service()
        d = svc.to_admin_dict(config)
        self.assertIn("id", d)
        self.assertIn("name", d)
        self.assertIn("provider_type", d)
        self.assertIn("enabled", d)
        self.assertIn("label", d)
        self.assertIn("config_json", d)
        self.assertNotIn("token", d)
        self.assertNotIn("secret", d)
        self.assertNotIn("password", d)


class TestPublicStatus(unittest.TestCase):

    # ── 15. aucune config ─────────────────────────────────────────────────────

    def test_public_status_no_config(self):
        svc = _make_service(None)
        self.assertEqual(svc.get_public_status(), {"enabled": False})

    # ── 16. config disabled ───────────────────────────────────────────────────

    def test_public_status_disabled_config(self):
        existing = IdentityProxyConfig(
            id="x", name="CF", provider_type="cloudflare_access",
            enabled=False, label="X", auto_login=False, auto_create_users=False,
            allowed_domains_json="[]", config_json=_cf_config_json(),
            created_at="2026-01-01T00:00:00", updated_at="2026-01-01T00:00:00",
        )
        svc = _make_service(existing)
        self.assertEqual(svc.get_public_status(), {"enabled": False})

    # ── 17. config enabled ────────────────────────────────────────────────────

    def test_public_status_enabled_config(self):
        existing = IdentityProxyConfig(
            id="x", name="CF", provider_type="cloudflare_access",
            enabled=True, label="Continue with Cloudflare Access",
            auto_login=True, auto_create_users=False,
            allowed_domains_json="[]", config_json=_cf_config_json(),
            created_at="2026-01-01T00:00:00", updated_at="2026-01-01T00:00:00",
        )
        svc = _make_service(existing)
        status = svc.get_public_status()
        self.assertTrue(status["enabled"])
        self.assertEqual(status["provider_type"], "cloudflare_access")
        self.assertIn("label", status)
        self.assertIn("auto_login", status)


class TestDeleteConfig(unittest.TestCase):

    # ── 18. delete lève erreur si inconnu ─────────────────────────────────────

    def test_delete_unknown_raises(self):
        svc = _make_service(None)
        with self.assertRaises(IdentityProxyConfigError):
            svc.delete_config("no-such-id")


if __name__ == "__main__":
    unittest.main(verbosity=2)
