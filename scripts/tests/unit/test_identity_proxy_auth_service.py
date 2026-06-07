#!/usr/bin/env python3
"""
Unit tests: IdentityProxyAuthService.

Repos and validators are fully mocked — no network, no DB.

Covers:
  1.  config absente → IdentityProxyDisabledError
  2.  config disabled → IdentityProxyDisabledError
  3.  single-user mode → IdentityProxyDisabledError
  4.  external identity existante → user retrouvé + last_used_at mis à jour
  5.  claims valides + user existant par email → token créé + identity liée
  6.  auto_create_users=false + aucun user → IdentityProxyUserError
  7.  auto_create_users=true + domaine autorisé → user créé role="user"
  8.  auto_create_users=true + domaine interdit → IdentityProxyUserError
  9.  user disabled → IdentityProxyUserError
  10. user expiré → IdentityProxyUserError
  11. aucun super_admin auto-créé
  12. get_public_status: single-user → disabled
  13. get_public_status: aucune config → disabled
  14. get_public_status: config enabled → champs publics

Run from project root:
    python3 scripts/tests/unit/test_identity_proxy_auth_service.py
"""

import json
import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.external_identity import ExternalIdentity
from backend.models.identity_proxy_claims import IdentityProxyClaims
from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.models.user import User
from backend.services_v2.identity_proxy_auth_service import IdentityProxyAuthService
from backend.services_v2.identity_proxy_validators.base import (
    IdentityProxyDisabledError,
    IdentityProxyUserError,
)

_MODULE = "backend.services_v2.identity_proxy_auth_service"

_TEAM_DOMAIN = "leang.cloudflareaccess.com"
_AUDIENCE = "test-audience"


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_settings(single_user_mode: bool = False):
    s = MagicMock()
    s.LINK2NAS_SINGLE_USER_MODE = single_user_mode
    return s


def _make_config(
    enabled: bool = True,
    auto_create_users: bool = False,
    allowed_domains_json: str = "[]",
) -> IdentityProxyConfig:
    return IdentityProxyConfig(
        id="cfg-1",
        name="CF Access",
        provider_type="cloudflare_access",
        enabled=enabled,
        label="Continue with Cloudflare Access",
        auto_login=False,
        auto_create_users=auto_create_users,
        allowed_domains_json=allowed_domains_json,
        config_json=json.dumps(
            {"team_domain": _TEAM_DOMAIN, "audience": _AUDIENCE}
        ),
        created_at="2026-01-01T00:00:00",
        updated_at="2026-01-01T00:00:00",
    )


def _make_user(
    *,
    is_active: bool = True,
    account_expires_at: str | None = None,
    role: str = "user",
) -> User:
    return User(
        id="user-1",
        email="alice@example.com",
        display_name="Alice",
        role=role,
        is_active=is_active,
        created_at="2026-01-01T00:00:00",
        updated_at="2026-01-01T00:00:00",
        account_expires_at=account_expires_at,
    )


def _make_claims(email: str = "alice@example.com") -> IdentityProxyClaims:
    return IdentityProxyClaims(
        provider_type="cloudflare_access",
        issuer=f"cloudflare_access:{_TEAM_DOMAIN}",
        subject="sub-abc",
        email=email,
        display_name="Alice",
    )


def _make_identity(user_id: str = "user-1") -> ExternalIdentity:
    return ExternalIdentity(
        id="ext-1",
        user_id=user_id,
        provider="identity_proxy",
        issuer=f"cloudflare_access:{_TEAM_DOMAIN}",
        subject="sub-abc",
        email="alice@example.com",
        linked_at="2026-01-01T00:00:00",
        last_used_at="2026-01-01T00:00:00",
    )


def _make_service(
    config: IdentityProxyConfig | None = None,
    user: User | None = None,
    identity: ExternalIdentity | None = None,
    single_user_mode: bool = False,
):
    settings = _make_settings(single_user_mode)

    config_repo = MagicMock()
    config_repo.get_first.return_value = config

    user_repo = MagicMock()
    user_repo.get_by_id.return_value = user
    user_repo.get_by_email.return_value = None

    ext_id_repo = MagicMock()
    ext_id_repo.get_by_issuer_subject.return_value = identity

    token_repo = MagicMock()

    svc = IdentityProxyAuthService(
        settings, config_repo, user_repo, ext_id_repo, token_repo
    )
    return svc, config_repo, user_repo, ext_id_repo, token_repo


def _mock_validator(claims: IdentityProxyClaims):
    mock_validator = MagicMock()
    mock_validator.validate_request.return_value = claims
    return mock_validator


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestAuthServiceDisabled(unittest.TestCase):

    # ── 1. config absente ─────────────────────────────────────────────────────

    def test_no_config_raises_disabled(self):
        svc, *_ = _make_service(config=None)
        with self.assertRaises(IdentityProxyDisabledError):
            svc.authenticate({})

    # ── 2. config disabled ────────────────────────────────────────────────────

    def test_disabled_config_raises(self):
        svc, *_ = _make_service(config=_make_config(enabled=False))
        with self.assertRaises(IdentityProxyDisabledError):
            svc.authenticate({})

    # ── 3. single-user mode ───────────────────────────────────────────────────

    def test_single_user_mode_raises(self):
        svc, *_ = _make_service(config=_make_config(), single_user_mode=True)
        with self.assertRaises(IdentityProxyDisabledError):
            svc.authenticate({})


class TestAuthServiceExternalIdentity(unittest.TestCase):

    # ── 4. external identity existante ────────────────────────────────────────

    def test_existing_identity_returns_user_and_updates_last_used(self):
        user = _make_user()
        identity = _make_identity()
        svc, _, user_repo, ext_id_repo, token_repo = _make_service(
            config=_make_config(), user=user, identity=identity
        )
        user_repo.get_by_id.return_value = user

        mock_v = _mock_validator(_make_claims())
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            raw_token, returned_user = svc.authenticate(
                {"Cf-Access-Jwt-Assertion": "tok"}
            )

        self.assertEqual(returned_user.id, "user-1")
        self.assertTrue(raw_token.startswith("l2n_"))
        ext_id_repo.update_last_used.assert_called_once()
        token_repo.create.assert_called_once()


class TestAuthServiceEmailLookup(unittest.TestCase):

    # ── 5. user existant par email ────────────────────────────────────────────

    def test_existing_user_by_email_links_identity(self):
        user = _make_user()
        svc, _, user_repo, ext_id_repo, token_repo = _make_service(
            config=_make_config(), identity=None
        )
        ext_id_repo.get_by_issuer_subject.return_value = None
        user_repo.get_by_email.return_value = user

        mock_v = _mock_validator(_make_claims())
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            raw_token, returned_user = svc.authenticate(
                {"Cf-Access-Jwt-Assertion": "tok"}
            )

        self.assertEqual(returned_user.id, "user-1")
        self.assertTrue(raw_token.startswith("l2n_"))
        ext_id_repo.create.assert_called_once()
        identity_arg = ext_id_repo.create.call_args[0][0]
        self.assertEqual(identity_arg.provider, "identity_proxy")
        self.assertEqual(identity_arg.user_id, "user-1")


class TestAuthServiceAutoCreate(unittest.TestCase):

    # ── 6. auto_create=false + aucun user ─────────────────────────────────────

    def test_no_user_auto_create_false_raises(self):
        svc, _, user_repo, ext_id_repo, _ = _make_service(
            config=_make_config(auto_create_users=False), identity=None
        )
        ext_id_repo.get_by_issuer_subject.return_value = None
        user_repo.get_by_email.return_value = None

        mock_v = _mock_validator(_make_claims())
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            with self.assertRaises(IdentityProxyUserError):
                svc.authenticate({"Cf-Access-Jwt-Assertion": "tok"})

    # ── 7. auto_create=true + domaine autorisé → role user ────────────────────

    def test_auto_create_allowed_domain_creates_user_role(self):
        cfg = _make_config(
            auto_create_users=True,
            allowed_domains_json='["example.com"]',
        )
        svc, _, user_repo, ext_id_repo, token_repo = _make_service(
            config=cfg, identity=None
        )
        ext_id_repo.get_by_issuer_subject.return_value = None
        user_repo.get_by_email.return_value = None

        mock_v = _mock_validator(_make_claims("alice@example.com"))
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            raw_token, created_user = svc.authenticate(
                {"Cf-Access-Jwt-Assertion": "tok"}
            )

        self.assertTrue(raw_token.startswith("l2n_"))
        user_repo.create.assert_called_once()
        created_arg = user_repo.create.call_args[0][0]
        self.assertEqual(created_arg.role, "user")
        self.assertTrue(created_arg.is_active)

    # ── 8. auto_create=true + domaine interdit ────────────────────────────────

    def test_auto_create_forbidden_domain_raises(self):
        cfg = _make_config(
            auto_create_users=True,
            allowed_domains_json='["corp.example.com"]',
        )
        svc, _, user_repo, ext_id_repo, _ = _make_service(config=cfg, identity=None)
        ext_id_repo.get_by_issuer_subject.return_value = None
        user_repo.get_by_email.return_value = None

        mock_v = _mock_validator(_make_claims("alice@other.com"))
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            with self.assertRaises(IdentityProxyUserError):
                svc.authenticate({"Cf-Access-Jwt-Assertion": "tok"})


class TestAuthServiceIneligibleUser(unittest.TestCase):

    # ── 9. user disabled ──────────────────────────────────────────────────────

    def test_disabled_user_raises(self):
        user = _make_user(is_active=False)
        identity = _make_identity()
        svc, _, user_repo, ext_id_repo, _ = _make_service(
            config=_make_config(), user=user, identity=identity
        )
        user_repo.get_by_id.return_value = user

        mock_v = _mock_validator(_make_claims())
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            with self.assertRaises(IdentityProxyUserError):
                svc.authenticate({"Cf-Access-Jwt-Assertion": "tok"})

    # ── 10. user expiré ───────────────────────────────────────────────────────

    def test_expired_user_raises(self):
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        user = _make_user(account_expires_at=past)
        identity = _make_identity()
        svc, _, user_repo, ext_id_repo, _ = _make_service(
            config=_make_config(), user=user, identity=identity
        )
        user_repo.get_by_id.return_value = user

        mock_v = _mock_validator(_make_claims())
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            with self.assertRaises(IdentityProxyUserError):
                svc.authenticate({"Cf-Access-Jwt-Assertion": "tok"})

    # ── 11. aucun super_admin auto-créé ───────────────────────────────────────

    def test_no_super_admin_auto_created(self):
        cfg = _make_config(auto_create_users=True)
        svc, _, user_repo, ext_id_repo, _ = _make_service(config=cfg, identity=None)
        ext_id_repo.get_by_issuer_subject.return_value = None
        user_repo.get_by_email.return_value = None

        mock_v = _mock_validator(_make_claims())
        with patch(
            f"{_MODULE}.get_identity_proxy_validator", return_value=mock_v
        ):
            svc.authenticate({"Cf-Access-Jwt-Assertion": "tok"})

        created_arg = user_repo.create.call_args[0][0]
        self.assertNotEqual(created_arg.role, "super_admin")
        self.assertNotEqual(created_arg.role, "admin")
        self.assertEqual(created_arg.role, "user")


class TestPublicStatus(unittest.TestCase):

    # ── 12. single-user → disabled ────────────────────────────────────────────

    def test_single_user_mode_public_status_disabled(self):
        svc, *_ = _make_service(single_user_mode=True)
        self.assertEqual(svc.get_public_status(True), {"enabled": False})

    # ── 13. aucune config → disabled ──────────────────────────────────────────

    def test_no_config_public_status_disabled(self):
        svc, *_ = _make_service(config=None)
        self.assertEqual(svc.get_public_status(False), {"enabled": False})

    # ── 14. config enabled → champs publics ───────────────────────────────────

    def test_enabled_config_public_status(self):
        svc, *_ = _make_service(config=_make_config(enabled=True))
        status = svc.get_public_status(False)
        self.assertTrue(status["enabled"])
        self.assertEqual(status["provider_type"], "cloudflare_access")
        self.assertIn("label", status)
        self.assertIn("auto_login", status)
        self.assertNotIn("config_json", status)
        self.assertNotIn("allowed_domains_json", status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
