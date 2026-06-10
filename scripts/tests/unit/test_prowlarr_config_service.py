#!/usr/bin/env python3
"""
Unit tests: ProwlarrConfigService (Bloc 1).

Uses in-memory fake repo and a real CryptoService.
No real DB, no network calls.

Covers:
  1.  Create global config — saved and returned
  2.  Create user config — saved and returned
  3.  API key is encrypted in storage (has enc:: prefix)
  4.  to_safe_dict never exposes api_key — only has_api_key
  5.  Priority: user config (enabled + base_url + key) > global config
  6.  Fallback to global when no user config
  7.  No config at all => source='none', available=False
  8.  User config disabled => fallback to global
  9.  enabled=True without base_url => ProwlarrConfigError
  10. enabled=True without api_key and no existing key => ProwlarrConfigError
  11. api_key="" or whitespace => treated as "keep existing", not an error
  12. api_key="" + enabled=True + no existing key => ProwlarrConfigError
  13. Update without api_key preserves existing encrypted key
  14. Update with api_key="" preserves existing encrypted key
  15. Update with api_key="   " preserves existing encrypted key
  16. Update with new api_key replaces encrypted key
  17. delete_global_config removes global
  18. delete_user_config removes user config
  19. User config disabled + global disabled => source='none'
  20. User config has no key + global has key => fallback to global
  21. Active config without base_url is not effective
  22. Active config without key is not effective

Run from project root:
    python3 scripts/tests/unit/test_prowlarr_config_service.py
"""

import os
import sys
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.prowlarr_config import ProwlarrConfig
from backend.services_v2.prowlarr_config_service import (
    ProwlarrConfigService,
    ProwlarrConfigError,
)
from backend.services_v2.crypto_service import CryptoService
from backend.utils.time import utc_now_iso

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_crypto() -> CryptoService:
    from cryptography.fernet import Fernet
    return CryptoService(Fernet.generate_key().decode())


# ── Fake repository ───────────────────────────────────────────────────────────

class FakeProwlarrConfigRepository:
    """In-memory fake: one global slot + one slot per user_id."""

    def __init__(self):
        self._global: ProwlarrConfig | None = None
        self._users: dict[str, ProwlarrConfig] = {}

    def get_global(self) -> ProwlarrConfig | None:
        return self._global

    def get_for_user(self, user_id: str) -> ProwlarrConfig | None:
        return self._users.get(user_id)

    def upsert(self, config: ProwlarrConfig) -> None:
        if config.scope == "global":
            self._global = config
        else:
            self._users[config.user_id] = config

    def delete_global(self) -> None:
        self._global = None

    def delete_for_user(self, user_id: str) -> None:
        self._users.pop(user_id, None)


def _make_service(repo=None, crypto=None):
    if repo is None:
        repo = FakeProwlarrConfigRepository()
    if crypto is None:
        crypto = _make_crypto()
    return ProwlarrConfigService(repository=repo, crypto_service=crypto), repo, crypto


def _insert_raw(repo, *, scope, user_id, enabled, base_url, encrypted_api_key):
    """Helper: bypass service validation to insert arbitrary state."""
    ts = utc_now_iso()
    repo.upsert(ProwlarrConfig(
        id=f"raw-{scope}-{user_id or 'global'}",
        scope=scope,
        user_id=user_id,
        enabled=enabled,
        base_url=base_url,
        encrypted_api_key=encrypted_api_key,
        label=None,
        tested_at=None,
        last_test_status=None,
        last_test_message=None,
        created_at=ts,
        updated_at=ts,
    ))


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestCreateGlobalConfig(unittest.TestCase):
    def test_create_global_config(self):
        svc, repo, _ = _make_service()
        cfg = svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="secret-key",
        )
        self.assertEqual(cfg.scope, "global")
        self.assertIsNone(cfg.user_id)
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.base_url, "https://prowlarr.example.com")
        self.assertIsNotNone(repo.get_global())


class TestCreateUserConfig(unittest.TestCase):
    def test_create_user_config(self):
        svc, repo, _ = _make_service()
        cfg = svc.save_user_config(
            user_id="user-1",
            enabled=True,
            base_url="https://my-prowlarr.example.com",
            api_key="user-secret",
        )
        self.assertEqual(cfg.scope, "user")
        self.assertEqual(cfg.user_id, "user-1")
        self.assertIsNotNone(repo.get_for_user("user-1"))


class TestApiKeyEncryption(unittest.TestCase):
    def test_api_key_encrypted_in_storage(self):
        svc, repo, _ = _make_service()
        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="my-raw-key",
        )
        stored = repo.get_global()
        self.assertIsNotNone(stored.encrypted_api_key)
        self.assertTrue(
            stored.encrypted_api_key.startswith("enc::"),
            "Stored key must have enc:: prefix",
        )
        self.assertNotEqual(stored.encrypted_api_key, "my-raw-key")

    def test_decrypted_key_matches_original(self):
        svc, repo, _ = _make_service()
        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="my-raw-key",
        )
        stored = repo.get_global()
        decrypted = svc.get_decrypted_api_key(stored)
        self.assertEqual(decrypted, "my-raw-key")


class TestToSafeDict(unittest.TestCase):
    def test_safe_dict_has_no_api_key(self):
        svc, _, _ = _make_service()
        cfg = svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="secret",
        )
        d = svc.to_safe_dict(cfg)
        self.assertNotIn("api_key", d)
        self.assertNotIn("encrypted_api_key", d)
        self.assertTrue(d["has_api_key"])

    def test_safe_dict_none_returns_none(self):
        svc, _, _ = _make_service()
        self.assertIsNone(svc.to_safe_dict(None))

    def test_safe_dict_no_key_has_api_key_false(self):
        svc, repo, _ = _make_service()
        _insert_raw(repo, scope="global", user_id=None, enabled=False,
                    base_url=None, encrypted_api_key=None)
        d = svc.to_safe_dict(repo.get_global())
        self.assertFalse(d["has_api_key"])


class TestResolveEffectiveConfig(unittest.TestCase):
    def test_user_priority_over_global(self):
        svc, _, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://global.example.com", api_key="global-key")
        svc.save_user_config(user_id="u1", enabled=True, base_url="https://user.example.com", api_key="user-key")
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "user")
        self.assertTrue(result.available)
        self.assertEqual(result.config.base_url, "https://user.example.com")

    def test_fallback_to_global_no_user_config(self):
        svc, _, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://global.example.com", api_key="global-key")
        result = svc.resolve_effective_config("u-no-config")
        self.assertEqual(result.source, "global")
        self.assertTrue(result.available)

    def test_no_config_at_all(self):
        svc, _, _ = _make_service()
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "none")
        self.assertFalse(result.available)
        self.assertIsNone(result.config)

    def test_user_config_disabled_falls_back_to_global(self):
        svc, _, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://global.example.com", api_key="global-key")
        svc.save_user_config(user_id="u1", enabled=False, base_url="https://user.example.com", api_key="user-key")
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "global")

    def test_both_disabled_returns_none(self):
        svc, _, _ = _make_service()
        svc.save_global_config(enabled=False, base_url="https://global.example.com", api_key="global-key")
        svc.save_user_config(user_id="u1", enabled=False, base_url="https://user.example.com", api_key="user-key")
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "none")
        self.assertFalse(result.available)

    def test_user_config_no_key_falls_back_to_global(self):
        """User config enabled + base_url but no encrypted_api_key => global used."""
        svc, repo, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://global.example.com", api_key="global-key")
        _insert_raw(repo, scope="user", user_id="u1", enabled=True,
                    base_url="https://user.example.com", encrypted_api_key=None)
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "global")

    def test_user_config_no_base_url_not_effective(self):
        """User config enabled + key but no base_url => not effective, falls back to global."""
        svc, repo, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://global.example.com", api_key="global-key")
        _insert_raw(repo, scope="user", user_id="u1", enabled=True,
                    base_url=None, encrypted_api_key="enc::some-key")
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "global")

    def test_global_config_no_base_url_not_effective(self):
        """Global config enabled + key but no base_url => not effective."""
        svc, repo, _ = _make_service()
        _insert_raw(repo, scope="global", user_id=None, enabled=True,
                    base_url=None, encrypted_api_key="enc::some-key")
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "none")

    def test_global_config_no_key_not_effective(self):
        """Global config enabled + base_url but no key => not effective."""
        svc, repo, _ = _make_service()
        _insert_raw(repo, scope="global", user_id=None, enabled=True,
                    base_url="https://global.example.com", encrypted_api_key=None)
        result = svc.resolve_effective_config("u1")
        self.assertEqual(result.source, "none")


class TestValidation(unittest.TestCase):
    def test_enabled_without_base_url_raises(self):
        svc, _, _ = _make_service()
        with self.assertRaises(ProwlarrConfigError):
            svc.save_global_config(enabled=True, base_url="", api_key="key")

    def test_enabled_without_base_url_none_raises(self):
        svc, _, _ = _make_service()
        with self.assertRaises(ProwlarrConfigError):
            svc.save_global_config(enabled=True, base_url=None, api_key="key")

    def test_enabled_without_api_key_no_existing_raises(self):
        svc, _, _ = _make_service()
        with self.assertRaises(ProwlarrConfigError):
            svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key=None)

    def test_enabled_with_empty_api_key_no_existing_raises(self):
        """api_key="" is treated as 'keep existing'; no existing key => error."""
        svc, _, _ = _make_service()
        with self.assertRaises(ProwlarrConfigError):
            svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key="")

    def test_enabled_with_whitespace_api_key_no_existing_raises(self):
        """api_key='   ' is treated as 'keep existing'; no existing key => error."""
        svc, _, _ = _make_service()
        with self.assertRaises(ProwlarrConfigError):
            svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key="   ")

    def test_disabled_without_key_or_url_is_valid(self):
        svc, _, _ = _make_service()
        cfg = svc.save_global_config(enabled=False, base_url=None, api_key=None)
        self.assertFalse(cfg.enabled)

    def test_user_enabled_without_base_url_raises(self):
        svc, _, _ = _make_service()
        with self.assertRaises(ProwlarrConfigError):
            svc.save_user_config(user_id="u1", enabled=True, base_url="", api_key="key")


class TestUpdateBehavior(unittest.TestCase):
    def test_update_without_api_key_preserves_existing_key(self):
        svc, repo, _ = _make_service()
        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="original-key",
        )
        original_encrypted = repo.get_global().encrypted_api_key

        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr-updated.example.com",
            api_key=None,
        )
        updated = repo.get_global()
        self.assertEqual(updated.encrypted_api_key, original_encrypted)
        self.assertEqual(updated.base_url, "https://prowlarr-updated.example.com")

    def test_update_with_empty_string_api_key_preserves_existing_key(self):
        """api_key="" must be treated as 'keep existing', not as an error."""
        svc, repo, _ = _make_service()
        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="original-key",
        )
        original_encrypted = repo.get_global().encrypted_api_key

        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="",
        )
        self.assertEqual(repo.get_global().encrypted_api_key, original_encrypted)

    def test_update_with_whitespace_api_key_preserves_existing_key(self):
        """api_key='   ' must be treated as 'keep existing', not as an error."""
        svc, repo, _ = _make_service()
        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="original-key",
        )
        original_encrypted = repo.get_global().encrypted_api_key

        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="   ",
        )
        self.assertEqual(repo.get_global().encrypted_api_key, original_encrypted)

    def test_update_with_new_api_key_replaces_encrypted_key(self):
        svc, repo, crypto = _make_service()
        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="original-key",
        )
        original_encrypted = repo.get_global().encrypted_api_key

        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="new-key",
        )
        updated = repo.get_global()
        self.assertNotEqual(updated.encrypted_api_key, original_encrypted)
        self.assertEqual(crypto.decrypt(updated.encrypted_api_key), "new-key")

    def test_update_preserves_id_and_created_at(self):
        svc, repo, _ = _make_service()
        svc.save_global_config(
            enabled=True,
            base_url="https://prowlarr.example.com",
            api_key="key",
        )
        original = repo.get_global()
        original_id = original.id
        original_created_at = original.created_at

        svc.save_global_config(enabled=False, base_url=None, api_key=None)
        updated = repo.get_global()
        self.assertEqual(updated.id, original_id)
        self.assertEqual(updated.created_at, original_created_at)

    def test_user_update_without_api_key_preserves_key(self):
        svc, repo, _ = _make_service()
        svc.save_user_config(user_id="u1", enabled=True, base_url="https://u.example.com", api_key="user-key")
        original_encrypted = repo.get_for_user("u1").encrypted_api_key

        svc.save_user_config(user_id="u1", enabled=True, base_url="https://u2.example.com", api_key=None)
        self.assertEqual(repo.get_for_user("u1").encrypted_api_key, original_encrypted)

    def test_enabled_without_api_key_but_existing_key_is_valid(self):
        """enabled=True + api_key=None + existing key present => valid."""
        svc, _, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key="initial-key")
        cfg = svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key=None)
        self.assertTrue(cfg.enabled)

    def test_enabled_with_empty_api_key_but_existing_key_is_valid(self):
        """enabled=True + api_key='' + existing key present => valid, key preserved."""
        svc, repo, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key="initial-key")
        original_encrypted = repo.get_global().encrypted_api_key
        cfg = svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key="")
        self.assertTrue(cfg.enabled)
        self.assertEqual(repo.get_global().encrypted_api_key, original_encrypted)


class TestDeleteConfig(unittest.TestCase):
    def test_delete_global_config(self):
        svc, repo, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key="key")
        self.assertIsNotNone(repo.get_global())
        svc.delete_global_config()
        self.assertIsNone(repo.get_global())

    def test_delete_user_config(self):
        svc, repo, _ = _make_service()
        svc.save_user_config(user_id="u1", enabled=True, base_url="https://u.example.com", api_key="key")
        self.assertIsNotNone(repo.get_for_user("u1"))
        svc.delete_user_config("u1")
        self.assertIsNone(repo.get_for_user("u1"))

    def test_delete_global_does_not_affect_users(self):
        svc, repo, _ = _make_service()
        svc.save_global_config(enabled=True, base_url="https://prowlarr.example.com", api_key="key")
        svc.save_user_config(user_id="u1", enabled=True, base_url="https://u.example.com", api_key="key")
        svc.delete_global_config()
        self.assertIsNone(repo.get_global())
        self.assertIsNotNone(repo.get_for_user("u1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
