#!/usr/bin/env python3
"""
Unit tests: OidcService (multi-provider).

Covers:
  initiate:
    1.  Happy path → (auth_url, state), state stored with provider_id
    2.  Unknown provider slug → OidcConfigError
    3.  Disabled provider → OidcDisabledError
    4.  Single-user mode → OidcDisabledError

  handle_callback:
    5.  Happy path → exchange_code returned, zero api_tokens created
    6.  Invalid state → OidcStateError
    7.  State belongs to different provider → OidcStateError
    8.  Unknown provider slug → OidcConfigError
    9.  Disabled provider → OidcDisabledError
    10. Single-user mode → OidcDisabledError
    11. email_verified false → OidcUserError
    12. No matching user, auto-create disabled → OidcUserError
    13. Disabled user → OidcUserError
    14. Expired user → OidcUserError

  complete_login:
    15. Happy path → api_token created, raw token returned, state deleted
    16. Invalid exchange_code → OidcExchangeError
    17. Exchange_code one-time use (second call raises) → OidcExchangeError
    18. User not found → OidcUserError
    19. Disabled user → OidcUserError
    20. Expired user → OidcUserError

Run from project root:
    python3 scripts/tests/unit/test_oidc_service.py
"""

import os
import sys
import uuid
import secrets
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.models.api_token import ApiToken
from backend.models.oidc_provider import OidcProvider
from backend.models.oidc_state import OidcState
from backend.models.user import User
from backend.services_v2.oidc_service import (
    OidcConfigError,
    OidcDisabledError,
    OidcExchangeError,
    OidcService,
    OidcStateError,
    OidcUserError,
)
from backend.utils.time import utc_now_iso


# ── Constants ─────────────────────────────────────────────────────────────────

_ISSUER = "https://idp.example.com"
_SUBJECT = "sub-test-001"
_EMAIL = "alice@example.com"
_PROVIDER_ID = "provider-id-fixed-for-tests"
_PROVIDER_SLUG = "test-provider"

_FAKE_METADATA = {
    "issuer": _ISSUER,
    "authorization_endpoint": f"{_ISSUER}/auth",
    "token_endpoint": f"{_ISSUER}/token",
    "jwks_uri": f"{_ISSUER}/jwks",
}

_BASE_CLAIMS = {
    "iss": _ISSUER,
    "sub": _SUBJECT,
    "email": _EMAIL,
    "email_verified": True,
    "name": "Alice Test",
    "aud": "test-client-id",
    "nonce": "irrelevant",
    "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
    "iat": int(datetime.now(UTC).timestamp()),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _future(s: int = 3600) -> str:
    return (datetime.now(UTC) + timedelta(seconds=s)).isoformat()


def _past(s: int = 3600) -> str:
    return (datetime.now(UTC) - timedelta(seconds=s)).isoformat()


def _user(is_active: bool = True, account_expires_at: str | None = None) -> User:
    ts = utc_now_iso()
    return User(
        id=str(uuid.uuid4()),
        email=_EMAIL,
        display_name="Alice",
        role="user",
        is_active=is_active,
        created_at=ts,
        updated_at=ts,
        account_expires_at=account_expires_at,
    )


def _make_test_provider(enabled: bool = True) -> OidcProvider:
    now = utc_now_iso()
    return OidcProvider(
        id=_PROVIDER_ID,
        name="Test Provider",
        slug=_PROVIDER_SLUG,
        enabled=enabled,
        issuer=_ISSUER,
        client_id="test-client-id",
        encrypted_client_secret="test-secret",
        scopes="openid email profile",
        button_label="Sign in with Test Provider",
        auto_create_users=False,
        allowed_domains_json="[]",
        state_ttl_seconds=600,
        exchange_code_ttl_seconds=60,
        sort_order=0,
        created_at=now,
        updated_at=now,
    )


# ── Fake repos ────────────────────────────────────────────────────────────────

class FakeSettings:
    LINK2NAS_SINGLE_USER_MODE = False
    PUBLIC_BASE_URL = "https://link2nas.example.com"


class FakeUserRepo:
    def __init__(self, users=None):
        self._id = {u.id: u for u in (users or [])}
        self._email = {u.email: u for u in (users or [])}

    def get_by_id(self, uid): return self._id.get(uid)
    def get_by_email(self, email): return self._email.get(email)
    def create(self, u):
        self._id[u.id] = u
        self._email[u.email] = u


class FakeExtIdRepo:
    def __init__(self):
        self._items = []

    def get_by_issuer_subject(self, issuer, sub):
        return next((i for i in self._items if i.issuer == issuer and i.subject == sub), None)

    def get_by_user_id(self, uid):
        return [i for i in self._items if i.user_id == uid]

    def create(self, identity): self._items.append(identity)
    def update_last_used(self, iid, ts): pass
    def count_by_issuer(self, issuer): return 0


class FakeOidcStateRepo:
    def __init__(self):
        self._states: dict = {}
        self._by_state: dict = {}
        self._by_exchange: dict = {}

    def create(self, s: OidcState):
        self._states[s.id] = s
        self._by_state[s.state] = s.id

    def get_valid_by_state(self, state_val: str, now_iso: str):
        sid = self._by_state.get(state_val)
        if not sid:
            return None
        s = self._states.get(sid)
        if s is None or s.consumed_at is not None or s.expires_at <= now_iso:
            return None
        if s.provider_id is None:
            return None
        return s

    def mark_callback_consumed(self, state_id, exchange_code, user_id, expires_at, consumed_at):
        s = self._states.get(state_id)
        if s:
            s = replace(s, exchange_code=exchange_code, user_id=user_id,
                        expires_at=expires_at, consumed_at=consumed_at)
            self._states[state_id] = s
            self._by_exchange[exchange_code] = state_id

    def get_valid_by_exchange_code(self, exchange_code: str, now_iso: str):
        sid = self._by_exchange.get(exchange_code)
        if not sid:
            return None
        s = self._states.get(sid)
        if s is None or s.consumed_at is None or s.user_id is None or s.expires_at <= now_iso:
            return None
        if s.provider_id is None:
            return None
        return s

    def delete(self, state_id: str):
        s = self._states.pop(state_id, None)
        if s:
            self._by_state.pop(s.state, None)
            if s.exchange_code:
                self._by_exchange.pop(s.exchange_code, None)

    def delete_expired(self, now_iso: str): pass


class FakeApiTokenRepo:
    def __init__(self):
        self._created: list = []

    def create(self, t: ApiToken): self._created.append(t)
    def count(self) -> int: return len(self._created)
    def last(self) -> ApiToken | None: return self._created[-1] if self._created else None


class FakeOidcProviderRepo:
    def __init__(self, providers=None):
        self._by_slug = {p.slug: p for p in (providers or [])}
        self._by_id = {p.id: p for p in (providers or [])}

    def get_by_slug(self, slug): return self._by_slug.get(slug)
    def get_by_id(self, pid): return self._by_id.get(pid)


class FakeCryptoService:
    def decrypt(self, value): return value
    def encrypt(self, value): return value


# ── Patched service (no HTTP, no JWT) ─────────────────────────────────────────

class _Svc(OidcService):
    """OidcService with HTTP and JWT decode replaced by configurable fakes."""

    def __init__(
        self, settings, user_repo, ext_id_repo, state_repo, token_repo,
        provider_repo=None, crypto_svc=None,
    ):
        super().__init__(
            settings, user_repo, ext_id_repo, state_repo, token_repo,
            provider_repo or FakeOidcProviderRepo([_make_test_provider()]),
            crypto_svc or FakeCryptoService(),
        )
        self._claims = dict(_BASE_CLAIMS)
        self._validate_raises: Exception | None = None

    def fetch_provider_metadata(self, issuer):
        return _FAKE_METADATA

    def exchange_authorization_code(self, metadata, code, client_id, client_secret, provider_slug):
        return {"id_token": "header.payload.sig", "access_token": "fake-access"}

    def validate_id_token(self, id_token, metadata, nonce, client_id, issuer):
        if self._validate_raises:
            raise self._validate_raises
        claims = dict(self._claims)
        claims["nonce"] = nonce
        email_verified = claims.get("email_verified", False)
        if isinstance(email_verified, str):
            email_verified = email_verified.lower() == "true"
        if not email_verified:
            raise OidcUserError("email_verified is not true")
        email = claims.get("email", "").strip().lower()
        if not email:
            raise OidcUserError("id_token missing email claim")
        claims["email"] = email
        return claims


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_state(state_repo: FakeOidcStateRepo, provider_id: str | None = None) -> OidcState:
    now = utc_now_iso()
    s = OidcState(
        id=str(uuid.uuid4()),
        state="state_" + secrets.token_urlsafe(16),
        nonce="nonce_" + secrets.token_urlsafe(16),
        created_at=now,
        expires_at=_future(600),
        provider_id=provider_id or _PROVIDER_ID,
    )
    state_repo.create(s)
    return s


def _make_consumed_state(state_repo: FakeOidcStateRepo, user_id: str) -> str:
    s = _make_state(state_repo)
    exchange_code = "ex_" + secrets.token_urlsafe(16)
    state_repo.mark_callback_consumed(
        state_id=s.id,
        exchange_code=exchange_code,
        user_id=user_id,
        expires_at=_future(60),
        consumed_at=utc_now_iso(),
    )
    return exchange_code


# ── Tests: initiate ───────────────────────────────────────────────────────────

class TestInitiate(unittest.TestCase):

    def _svc(self, **setting_overrides):
        settings = FakeSettings()
        for k, v in setting_overrides.items():
            setattr(settings, k, v)
        self.state_repo = FakeOidcStateRepo()
        return _Svc(settings, FakeUserRepo(), FakeExtIdRepo(), self.state_repo, FakeApiTokenRepo())

    # 1. Happy path
    def test_happy_path_returns_auth_url_and_state(self):
        from urllib.parse import unquote
        svc = self._svc()
        auth_url, state = svc.initiate(_PROVIDER_SLUG)

        self.assertIsInstance(auth_url, str)
        self.assertIn("https://idp.example.com/auth", auth_url)
        # redirect_uri is URL-encoded in the query string; decode to verify slug is in the path
        self.assertIn(f"/{_PROVIDER_SLUG}/callback", unquote(auth_url))
        self.assertIsInstance(state, str)
        self.assertGreater(len(state), 16)

    # 2. Unknown provider slug
    def test_unknown_slug_raises_config_error(self):
        svc = self._svc()
        with self.assertRaises(OidcConfigError):
            svc.initiate("no-such-provider")

    # 3. Disabled provider
    def test_disabled_provider_raises(self):
        settings = FakeSettings()
        self.state_repo = FakeOidcStateRepo()
        provider_repo = FakeOidcProviderRepo([_make_test_provider(enabled=False)])
        svc = _Svc(
            settings, FakeUserRepo(), FakeExtIdRepo(),
            self.state_repo, FakeApiTokenRepo(),
            provider_repo=provider_repo,
        )
        with self.assertRaises(OidcDisabledError):
            svc.initiate(_PROVIDER_SLUG)

    # 4. Single-user mode
    def test_single_user_mode_raises(self):
        svc = self._svc(LINK2NAS_SINGLE_USER_MODE=True)
        with self.assertRaises(OidcDisabledError):
            svc.initiate(_PROVIDER_SLUG)

    # 4b. Legacy OIDC_ENABLED=False does NOT disable a DB-configured provider
    def test_legacy_oidc_enabled_false_does_not_disable_db_provider(self):
        from urllib.parse import unquote
        svc = self._svc(OIDC_ENABLED=False)
        auth_url, state = svc.initiate(_PROVIDER_SLUG)
        self.assertIn("client_id=test-client-id", unquote(auth_url))
        self.assertGreater(len(state), 16)


# ── Tests: handle_callback ────────────────────────────────────────────────────

class TestHandleCallback(unittest.TestCase):

    def _svc(self, user=None, provider_repo=None, **setting_overrides):
        u = user or _user()
        settings = FakeSettings()
        for k, v in setting_overrides.items():
            setattr(settings, k, v)
        self.token_repo = FakeApiTokenRepo()
        self.state_repo = FakeOidcStateRepo()
        svc = _Svc(
            settings, FakeUserRepo([u]), FakeExtIdRepo(),
            self.state_repo, self.token_repo,
            provider_repo=provider_repo,
        )
        return svc, u

    # 5. Happy path
    def test_happy_path_returns_exchange_code_no_token_created(self):
        svc, _ = self._svc()
        s = _make_state(self.state_repo)

        result = svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code-xxx")

        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 16)
        self.assertEqual(self.token_repo.count(), 0,
                         "handle_callback must NOT create any api_token")

    # 6. Invalid state
    def test_invalid_state_raises(self):
        svc, _ = self._svc()
        with self.assertRaises(OidcStateError):
            svc.handle_callback(_PROVIDER_SLUG, "no-such-state", "auth-code")

    # 7. State belongs to a different provider
    def test_state_wrong_provider_raises(self):
        svc, _ = self._svc()
        other_provider_id = str(uuid.uuid4())
        s = _make_state(self.state_repo, provider_id=other_provider_id)
        with self.assertRaises(OidcStateError):
            svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code")

    # 8. Unknown provider slug
    def test_unknown_slug_raises_config_error(self):
        svc, _ = self._svc()
        s = _make_state(self.state_repo)
        with self.assertRaises(OidcConfigError):
            svc.handle_callback("no-such-provider", s.state, "auth-code")

    # 9. Disabled provider
    def test_disabled_provider_raises(self):
        provider_repo = FakeOidcProviderRepo([_make_test_provider(enabled=False)])
        svc, _ = self._svc(provider_repo=provider_repo)
        s = _make_state(self.state_repo)
        with self.assertRaises(OidcDisabledError):
            svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code")

    # 10. Single-user mode
    def test_single_user_mode_raises(self):
        svc, _ = self._svc(LINK2NAS_SINGLE_USER_MODE=True)
        s = _make_state(self.state_repo)
        with self.assertRaises(OidcDisabledError):
            svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code")

    # 11. email_verified false
    def test_email_not_verified_raises_no_token(self):
        svc, _ = self._svc()
        svc._claims["email_verified"] = False
        s = _make_state(self.state_repo)
        with self.assertRaises(OidcUserError):
            svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code")
        self.assertEqual(self.token_repo.count(), 0)

    # 12. No matching user, auto-create disabled
    def test_auto_create_disabled_no_user_raises(self):
        settings = FakeSettings()
        self.token_repo = FakeApiTokenRepo()
        self.state_repo = FakeOidcStateRepo()
        svc = _Svc(settings, FakeUserRepo(), FakeExtIdRepo(), self.state_repo, self.token_repo)
        s = _make_state(self.state_repo)
        with self.assertRaises(OidcUserError):
            svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code")
        self.assertEqual(self.token_repo.count(), 0)

    # 13. Disabled user
    def test_disabled_user_raises_no_token(self):
        svc, _ = self._svc(user=_user(is_active=False))
        s = _make_state(self.state_repo)
        with self.assertRaises(OidcUserError):
            svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code")
        self.assertEqual(self.token_repo.count(), 0)

    # 14. Expired user
    def test_expired_user_raises_no_token(self):
        svc, _ = self._svc(user=_user(account_expires_at=_past(3600)))
        s = _make_state(self.state_repo)
        with self.assertRaises(OidcUserError):
            svc.handle_callback(_PROVIDER_SLUG, s.state, "auth-code")
        self.assertEqual(self.token_repo.count(), 0)


# ── Tests: complete_login ─────────────────────────────────────────────────────

class TestCompleteLogin(unittest.TestCase):

    def _svc(self, user=None):
        u = user or _user()
        self.user_repo = FakeUserRepo([u])
        self.token_repo = FakeApiTokenRepo()
        self.state_repo = FakeOidcStateRepo()
        svc = _Svc(FakeSettings(), self.user_repo, FakeExtIdRepo(), self.state_repo, self.token_repo)
        return svc, u

    # 15. Happy path
    def test_happy_path_creates_token_deletes_state(self):
        svc, u = self._svc()
        exchange_code = _make_consumed_state(self.state_repo, u.id)

        raw_token, returned_user = svc.complete_login(exchange_code)

        self.assertIsInstance(raw_token, str)
        self.assertTrue(raw_token.startswith("l2n_"))
        self.assertEqual(returned_user.id, u.id)
        self.assertEqual(self.token_repo.count(), 1)
        self.assertIsNone(
            self.state_repo.get_valid_by_exchange_code(exchange_code, utc_now_iso()),
            "OidcState must be deleted after complete_login",
        )

    # 16. Invalid exchange_code
    def test_invalid_exchange_code_raises(self):
        svc, _ = self._svc()
        with self.assertRaises(OidcExchangeError):
            svc.complete_login("no-such-exchange-code")

    # 17. One-time use
    def test_exchange_code_one_time_use(self):
        svc, u = self._svc()
        exchange_code = _make_consumed_state(self.state_repo, u.id)

        svc.complete_login(exchange_code)

        with self.assertRaises(OidcExchangeError):
            svc.complete_login(exchange_code)

        self.assertEqual(self.token_repo.count(), 1,
                         "Only one token must exist after two calls with the same exchange_code")

    # 18. User not found
    def test_user_not_found_raises_no_token(self):
        svc, _ = self._svc()
        exchange_code = _make_consumed_state(self.state_repo, str(uuid.uuid4()))
        with self.assertRaises(OidcUserError):
            svc.complete_login(exchange_code)
        self.assertEqual(self.token_repo.count(), 0)

    # 19. Disabled user
    def test_disabled_user_raises_no_token(self):
        svc, u = self._svc(user=_user(is_active=False))
        exchange_code = _make_consumed_state(self.state_repo, u.id)
        with self.assertRaises(OidcUserError):
            svc.complete_login(exchange_code)
        self.assertEqual(self.token_repo.count(), 0)

    # 20. Expired user
    def test_expired_user_raises_no_token(self):
        svc, u = self._svc(user=_user(account_expires_at=_past(3600)))
        exchange_code = _make_consumed_state(self.state_repo, u.id)
        with self.assertRaises(OidcUserError):
            svc.complete_login(exchange_code)
        self.assertEqual(self.token_repo.count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
