#!/usr/bin/env python3
"""
Unit tests: CloudflareAccessValidator.

No real network calls — PyJWKClient and jwt.decode are mocked.

Covers:
  1.  header absent → IdentityProxyValidationError
  2.  team_domain manquant dans config_json → IdentityProxyConfigError
  3.  audience manquante dans config_json → IdentityProxyConfigError
  4.  config_json invalide (non-JSON) → IdentityProxyConfigError
  5.  token valide → claims corrects (provider_type, issuer, subject, email, display_name)
  6.  token valide sans name → display_name None
  7.  email manquant → IdentityProxyValidationError
  8.  sub manquant → IdentityProxyValidationError
  9.  email normalisé (upper + spaces)
  10. token expiré → IdentityProxyValidationError (message générique)
  11. audience invalide → IdentityProxyValidationError
  12. issuer invalide → IdentityProxyValidationError
  13. decode error générique → IdentityProxyValidationError
  14. JWKS resolution failure → IdentityProxyValidationError
  15. pas de fuite du token dans les messages d'erreur

Run from project root:
    python3 scripts/tests/unit/test_cloudflare_access_validator.py
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import jwt as _jwt

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.identity_proxy_config import IdentityProxyConfig
from backend.services_v2.identity_proxy_validators.cloudflare_access import (
    CloudflareAccessValidator,
)
from backend.services_v2.identity_proxy_validators.base import (
    IdentityProxyConfigError,
    IdentityProxyValidationError,
)

_MODULE = "backend.services_v2.identity_proxy_validators.cloudflare_access"

_TEAM_DOMAIN = "leang.cloudflareaccess.com"
_AUDIENCE = "test-audience"
_FAKE_TOKEN = "header.payload.sig"

_CONFIG_JSON = json.dumps({"team_domain": _TEAM_DOMAIN, "audience": _AUDIENCE})

_VALID_CLAIMS = {
    "sub": "user-abc-123",
    "email": "alice@example.com",
    "name": "Alice Smith",
    "iss": f"https://{_TEAM_DOMAIN}",
    "aud": _AUDIENCE,
    "exp": 9999999999,
    "iat": 1000000000,
}


def _make_config(config_json: str = _CONFIG_JSON) -> IdentityProxyConfig:
    return IdentityProxyConfig(
        id="cfg-1",
        name="CF Access",
        provider_type="cloudflare_access",
        enabled=True,
        label="Continue with Cloudflare Access",
        auto_login=False,
        auto_create_users=False,
        allowed_domains_json="[]",
        config_json=config_json,
        created_at="2026-01-01T00:00:00",
        updated_at="2026-01-01T00:00:00",
    )


def _patch_jwks(return_value: dict | None = None, side_effect=None):
    """Patches PyJWKClient + jwt.decode together for one test."""
    mock_jwks_cls = MagicMock()
    mock_instance = MagicMock()
    mock_jwks_cls.return_value = mock_instance
    mock_signing_key = MagicMock()
    mock_instance.get_signing_key_from_jwt.return_value = mock_signing_key

    mock_decode = MagicMock()
    if side_effect is not None:
        mock_decode.side_effect = side_effect
    else:
        mock_decode.return_value = return_value or _VALID_CLAIMS

    return mock_jwks_cls, mock_decode, mock_signing_key


class TestCloudflareAccessValidator(unittest.TestCase):

    def setUp(self):
        self.validator = CloudflareAccessValidator()

    # ── 1. header absent ──────────────────────────────────────────────────────

    def test_missing_header_raises(self):
        with self.assertRaises(IdentityProxyValidationError) as ctx:
            self.validator.validate_request({}, _make_config())
        self.assertIn("Cf-Access-Jwt-Assertion", str(ctx.exception))

    # ── 2. team_domain manquant ───────────────────────────────────────────────

    def test_missing_team_domain_raises(self):
        cfg = _make_config(json.dumps({"audience": "x"}))
        with self.assertRaises(IdentityProxyConfigError):
            self.validator.validate_request(
                {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, cfg
            )

    # ── 3. audience manquante ─────────────────────────────────────────────────

    def test_missing_audience_raises(self):
        cfg = _make_config(json.dumps({"team_domain": _TEAM_DOMAIN}))
        with self.assertRaises(IdentityProxyConfigError):
            self.validator.validate_request(
                {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, cfg
            )

    # ── 4. config_json invalide ───────────────────────────────────────────────

    def test_invalid_config_json_raises(self):
        cfg = _make_config("not-json")
        with self.assertRaises(IdentityProxyConfigError):
            self.validator.validate_request(
                {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, cfg
            )

    # ── 5. token valide → claims corrects ────────────────────────────────────

    def test_valid_token_returns_correct_claims(self):
        mock_jwks, mock_decode, _ = _patch_jwks(_VALID_CLAIMS)
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            result = self.validator.validate_request(
                {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
            )
        self.assertEqual(result.provider_type, "cloudflare_access")
        self.assertEqual(result.issuer, f"cloudflare_access:{_TEAM_DOMAIN}")
        self.assertEqual(result.subject, "user-abc-123")
        self.assertEqual(result.email, "alice@example.com")
        self.assertEqual(result.display_name, "Alice Smith")

    # ── 6. token valide sans name → display_name None ─────────────────────────

    def test_valid_token_no_name_display_name_none(self):
        claims = {**_VALID_CLAIMS}
        claims.pop("name", None)
        mock_jwks, mock_decode, _ = _patch_jwks(claims)
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            result = self.validator.validate_request(
                {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
            )
        self.assertIsNone(result.display_name)

    # ── 7. email manquant ─────────────────────────────────────────────────────

    def test_missing_email_raises(self):
        claims = {k: v for k, v in _VALID_CLAIMS.items() if k != "email"}
        mock_jwks, mock_decode, _ = _patch_jwks(claims)
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            with self.assertRaises(IdentityProxyValidationError):
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
                )

    # ── 8. sub manquant ───────────────────────────────────────────────────────

    def test_missing_sub_raises(self):
        claims = {k: v for k, v in _VALID_CLAIMS.items() if k != "sub"}
        mock_jwks, mock_decode, _ = _patch_jwks(claims)
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            with self.assertRaises(IdentityProxyValidationError):
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
                )

    # ── 9. email normalisé ────────────────────────────────────────────────────

    def test_email_normalized(self):
        claims = {**_VALID_CLAIMS, "email": "  ALICE@EXAMPLE.COM  "}
        mock_jwks, mock_decode, _ = _patch_jwks(claims)
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            result = self.validator.validate_request(
                {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
            )
        self.assertEqual(result.email, "alice@example.com")

    # ── 10. token expiré ──────────────────────────────────────────────────────

    def test_expired_token_raises_validation_error(self):
        mock_jwks, mock_decode, _ = _patch_jwks(
            side_effect=_jwt.ExpiredSignatureError("expired")
        )
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            with self.assertRaises(IdentityProxyValidationError):
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
                )

    # ── 11. audience invalide ─────────────────────────────────────────────────

    def test_invalid_audience_raises(self):
        mock_jwks, mock_decode, _ = _patch_jwks(
            side_effect=_jwt.InvalidAudienceError("bad aud")
        )
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            with self.assertRaises(IdentityProxyValidationError):
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
                )

    # ── 12. issuer invalide ───────────────────────────────────────────────────

    def test_invalid_issuer_raises(self):
        mock_jwks, mock_decode, _ = _patch_jwks(
            side_effect=_jwt.InvalidIssuerError("bad iss")
        )
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            with self.assertRaises(IdentityProxyValidationError):
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
                )

    # ── 13. decode error générique ────────────────────────────────────────────

    def test_decode_error_raises(self):
        mock_jwks, mock_decode, _ = _patch_jwks(
            side_effect=_jwt.DecodeError("bad token")
        )
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            with self.assertRaises(IdentityProxyValidationError):
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
                )

    # ── 14. JWKS resolution failure ───────────────────────────────────────────

    def test_jwks_resolution_failure_raises(self):
        mock_jwks_cls = MagicMock()
        mock_instance = MagicMock()
        mock_jwks_cls.return_value = mock_instance
        mock_instance.get_signing_key_from_jwt.side_effect = Exception("network error")

        with patch(f"{_MODULE}.PyJWKClient", mock_jwks_cls):
            with self.assertRaises(IdentityProxyValidationError):
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": _FAKE_TOKEN}, _make_config()
                )

    # ── 15. pas de fuite du token dans les erreurs ───────────────────────────

    def test_no_token_leak_in_header_error(self):
        secret_token = "super.secret.jwt.value"
        try:
            self.validator.validate_request(
                {"Cf-Access-Jwt-Assertion": secret_token},
                _make_config("not-json"),
            )
        except IdentityProxyConfigError as exc:
            self.assertNotIn(secret_token, str(exc))

    def test_no_token_leak_in_decode_error(self):
        secret_token = "super.secret.jwt.value"
        mock_jwks, mock_decode, _ = _patch_jwks(
            side_effect=_jwt.DecodeError("bad token")
        )
        with patch(f"{_MODULE}.PyJWKClient", mock_jwks), \
             patch(f"{_MODULE}.jwt.decode", mock_decode):
            try:
                self.validator.validate_request(
                    {"Cf-Access-Jwt-Assertion": secret_token}, _make_config()
                )
            except IdentityProxyValidationError as exc:
                self.assertNotIn(secret_token, str(exc))


if __name__ == "__main__":
    unittest.main(verbosity=2)
