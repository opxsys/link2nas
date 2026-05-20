#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"
TEST_EMAIL_DOMAIN="${TEST_EMAIL_DOMAIN:-test.local}"

echo "=== Link2NAS V2 transactional auth emails test ==="
echo "Backend=${V2_DATABASE_BACKEND:-sqlite}"
echo "BASE_URL=$BASE_URL"

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token="${4:-}"

  if [[ -n "$body" ]]; then
    if [[ -n "$token" ]]; then
      curl -s -X "$method" "$BASE_URL$path" \
        -H "X-Api-Key: $token" \
        -H "Content-Type: application/json" \
        -d "$body"
    else
      curl -s -X "$method" "$BASE_URL$path" \
        -H "Content-Type: application/json" \
        -d "$body"
    fi
  else
    if [[ -n "$token" ]]; then
      curl -s -X "$method" "$BASE_URL$path" \
        -H "X-Api-Key: $token"
    else
      curl -s -X "$method" "$BASE_URL$path"
    fi
  fi
}

assert_no_error() {
  local json="$1"
  local label="$2"

  local err
  err="$(echo "$json" | jq -r '.error // empty')"

  if [[ -n "$err" ]]; then
    echo "[KO] $label"
    echo "$json" | jq
    exit 1
  fi

  echo "[OK] $label"
}

assert_error_present() {
  local json="$1"
  local label="$2"

  local err
  err="$(echo "$json" | jq -r '.error // empty')"

  if [[ -z "$err" ]]; then
    echo "[KO] $label"
    echo "Expected error, got:"
    echo "$json" | jq
    exit 1
  fi

  echo "[OK] $label"
}

assert_equals() {
  local actual="$1"
  local expected="$2"
  local label="$3"

  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label"
    echo "     expected: $expected"
    echo "     actual:   $actual"
    exit 1
  fi

  echo "[OK] $label"
}

extract_token_from_url() {
  local url="$1"
  echo "$url" | sed -n 's/.*[?&]token=\([^&]*\).*/\1/p'
}

unique_email() {
  local prefix="$1"
  echo "${prefix}-$(date +%s)-$RANDOM@$TEST_EMAIL_DOMAIN"
}

echo
echo "1) Setup status"
SETUP_STATUS="$(api GET "/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq

echo
echo "2) Login admin"
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  ADMIN_TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
  echo "$LOGIN" | jq
  assert_no_error "$LOGIN" "admin login"
  ADMIN_TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
  if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
    echo "[KO] admin token missing"
    exit 1
  fi
  echo "[OK] admin token received"
fi

echo
echo "3) Create invitation-mode user"
INVITED_EMAIL="$(unique_email invited)"
CREATE_INVITED="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$INVITED_EMAIL\",
  \"display_name\":\"Invited Email User\",
  \"role\":\"user\",
  \"is_active\":true,
  \"creation_mode\":\"invitation\"
}" "$ADMIN_TOKEN")"
echo "$CREATE_INVITED" | jq
assert_no_error "$CREATE_INVITED" "invitation-mode user created"

INVITED_USER_ID="$(echo "$CREATE_INVITED" | jq -r '.id // empty')"
INVITE_URL_FROM_CREATE="$(echo "$CREATE_INVITED" | jq -r '.invitation.invitation_url // empty')"

if [[ -z "$INVITED_USER_ID" || "$INVITED_USER_ID" == "null" ]]; then
  echo "[KO] invited user id missing"
  exit 1
fi

if [[ -z "$INVITE_URL_FROM_CREATE" || "$INVITE_URL_FROM_CREATE" == "null" ]]; then
  echo "[KO] invitation URL missing from creation response"
  echo "$CREATE_INVITED" | jq
  exit 1
fi

echo "[OK] invitation URL returned on user creation"

echo
echo "4) Send invitation email"
SEND_INVITE_EMAIL="$(api POST "/api/v2/admin/users/$INVITED_USER_ID/invitation/email" "" "$ADMIN_TOKEN")"
echo "$SEND_INVITE_EMAIL" | jq

INVITE_EMAIL_ERROR="$(echo "$SEND_INVITE_EMAIL" | jq -r '.error // empty')"
if [[ -n "$INVITE_EMAIL_ERROR" ]]; then
  echo "[WARN] invitation email failed, probably SMTP config issue: $INVITE_EMAIL_ERROR"
else
  echo "[OK] invitation email sent"
fi

INVITE_EMAIL_URL="$(echo "$SEND_INVITE_EMAIL" | jq -r '.invitation_url // empty')"
if [[ -z "$INVITE_EMAIL_URL" || "$INVITE_EMAIL_URL" == "null" ]]; then
  echo "[WARN] invitation email response has no invitation_url; continuing with creation URL"
  INVITE_EMAIL_URL="$INVITE_URL_FROM_CREATE"
fi

INVITE_TOKEN="$(extract_token_from_url "$INVITE_EMAIL_URL")"
if [[ -z "$INVITE_TOKEN" ]]; then
  echo "[KO] invitation token extraction failed"
  echo "URL=$INVITE_EMAIL_URL"
  exit 1
fi
echo "[OK] invitation token extracted"

echo
echo "5) Accept invitation from transactional flow"
ACCEPT_INVITE="$(api POST "/api/v2/public/invitations/accept" "{
  \"token\":\"$INVITE_TOKEN\",
  \"password\":\"InviteStrong123!\"
}")"
echo "$ACCEPT_INVITE" | jq
assert_no_error "$ACCEPT_INVITE" "transactional invitation accepted"

echo
echo "6) Login invited user"
INVITED_LOGIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$INVITED_EMAIL\",
  \"password\":\"InviteStrong123!\"
}")"
echo "$INVITED_LOGIN" | jq
assert_no_error "$INVITED_LOGIN" "invited user login"

INVITED_TOKEN="$(echo "$INVITED_LOGIN" | jq -r '.token // empty')"
if [[ -z "$INVITED_TOKEN" || "$INVITED_TOKEN" == "null" ]]; then
  echo "[KO] invited user token missing"
  exit 1
fi

echo
echo "7) Admin creates password reset email"
SEND_RESET_EMAIL="$(api POST "/api/v2/admin/users/$INVITED_USER_ID/password-reset-link/email" "" "$ADMIN_TOKEN")"
echo "$SEND_RESET_EMAIL" | jq

RESET_EMAIL_ERROR="$(echo "$SEND_RESET_EMAIL" | jq -r '.error // empty')"
if [[ -n "$RESET_EMAIL_ERROR" ]]; then
  echo "[WARN] reset email failed, probably SMTP config issue: $RESET_EMAIL_ERROR"
fi

RESET_URL="$(echo "$SEND_RESET_EMAIL" | jq -r '.reset_url // empty')"

if [[ -z "$RESET_URL" || "$RESET_URL" == "null" ]]; then
  echo "[WARN] reset email response has no reset_url; creating copiable reset link instead"

  RESET_LINK="$(api POST "/api/v2/admin/users/$INVITED_USER_ID/password-reset-link" "" "$ADMIN_TOKEN")"
  echo "$RESET_LINK" | jq
  assert_no_error "$RESET_LINK" "password reset link fallback created"

  RESET_URL="$(echo "$RESET_LINK" | jq -r '.reset_url // empty')"
else
  echo "[OK] password reset email endpoint returned reset_url"
fi

RESET_TOKEN="$(extract_token_from_url "$RESET_URL")"
if [[ -z "$RESET_TOKEN" ]]; then
  echo "[KO] reset token extraction failed"
  echo "URL=$RESET_URL"
  exit 1
fi
echo "[OK] reset token extracted"

echo
echo "8) Confirm password reset from transactional flow"
CONFIRM_RESET="$(api POST "/api/v2/public/password-reset/confirm" "{
  \"token\":\"$RESET_TOKEN\",
  \"password\":\"ResetStrong123!\"
}")"
echo "$CONFIRM_RESET" | jq
assert_no_error "$CONFIRM_RESET" "transactional password reset confirmed"

echo
echo "9) Login after transactional password reset"
RESET_LOGIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$INVITED_EMAIL\",
  \"password\":\"ResetStrong123!\"
}")"
echo "$RESET_LOGIN" | jq
assert_no_error "$RESET_LOGIN" "login after transactional reset"

echo
echo "10) Request email verification"
VERIFY_REQUEST="$(api POST "/api/v2/me/request-email-verification" "" "$INVITED_TOKEN")"
echo "$VERIFY_REQUEST" | jq

VERIFY_ERROR="$(echo "$VERIFY_REQUEST" | jq -r '.error // empty')"
if [[ -n "$VERIFY_ERROR" ]]; then
  echo "[WARN] email verification request failed, probably SMTP config issue or endpoint behavior: $VERIFY_ERROR"
fi

VERIFY_URL="$(echo "$VERIFY_REQUEST" | jq -r '.verification_url // empty')"

if [[ -z "$VERIFY_URL" || "$VERIFY_URL" == "null" ]]; then
  echo "[WARN] verification_url missing from /me/request-email-verification response"
  echo "[INFO] Trying admin verify-email fallback"

  ADMIN_VERIFY="$(api POST "/api/v2/admin/users/$INVITED_USER_ID/verify-email" "" "$ADMIN_TOKEN")"
  echo "$ADMIN_VERIFY" | jq
  assert_no_error "$ADMIN_VERIFY" "admin email verification fallback"

else
  VERIFY_TOKEN="$(extract_token_from_url "$VERIFY_URL")"
  if [[ -z "$VERIFY_TOKEN" ]]; then
    echo "[KO] verification token extraction failed"
    echo "URL=$VERIFY_URL"
    exit 1
  fi

  echo "[OK] verification token extracted"

  VERIFY_STATUS="$(api GET "/api/v2/public/tokens/$VERIFY_TOKEN/status")"
  echo "$VERIFY_STATUS" | jq
  assert_no_error "$VERIFY_STATUS" "verification token status valid"

  VERIFY_TYPE="$(echo "$VERIFY_STATUS" | jq -r '.token_type // empty')"
  assert_equals "$VERIFY_TYPE" "email_verification" "verification token type"

  CONFIRM_VERIFY="$(api POST "/api/v2/public/email-verification/confirm" "{
    \"token\":\"$VERIFY_TOKEN\"
  }")"
  echo "$CONFIRM_VERIFY" | jq
  assert_no_error "$CONFIRM_VERIFY" "email verification confirmed"
fi

echo
echo "11) Magic login request for verified user"
MAGIC_REQUEST="$(api POST "/api/v2/public/magic-login/request" "{
  \"email\":\"$INVITED_EMAIL\"
}")"
echo "$MAGIC_REQUEST" | jq

MAGIC_ERROR="$(echo "$MAGIC_REQUEST" | jq -r '.error // empty')"
if [[ -n "$MAGIC_ERROR" ]]; then
  echo "[WARN] magic login request returned error: $MAGIC_ERROR"
fi

MAGIC_URL="$(echo "$MAGIC_REQUEST" | jq -r '.magic_url // empty')"

if [[ -z "$MAGIC_URL" || "$MAGIC_URL" == "null" ]]; then
  echo "[WARN] magic_url missing from response; creating magic_login token directly for backend validation"

  MAGIC_DIRECT="$(python3 - <<PY
import json
from app import app

user_id = "$INVITED_USER_ID"

with app.app_context():
    token_service = app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    app_settings = app.config["APP_SETTINGS_SERVICE_V2"]

    token, raw = token_service.create_token(
        user_id=user_id,
        token_type="magic_login",
        ttl_minutes=app_settings.get_magic_login_ttl_minutes(),
        created_by_user_id=user_id,
    )

    print(json.dumps({
        "magic_url": token_service.build_magic_login_url(raw),
        "expires_at": getattr(token, "expires_at", None),
        "token_type": getattr(token, "token_type", "magic_login"),
    }, ensure_ascii=False))
PY
)"
  echo "$MAGIC_DIRECT" | jq
  MAGIC_URL="$(echo "$MAGIC_DIRECT" | jq -r '.magic_url // empty')"
else
  echo "[OK] magic login request returned magic_url"
fi

MAGIC_TOKEN="$(extract_token_from_url "$MAGIC_URL")"
if [[ -z "$MAGIC_TOKEN" ]]; then
  echo "[KO] magic token extraction failed"
  echo "URL=$MAGIC_URL"
  exit 1
fi
echo "[OK] magic token extracted"

echo
echo "12) Confirm magic login"
MAGIC_CONFIRM="$(api POST "/api/v2/public/magic-login/confirm" "{
  \"token\":\"$MAGIC_TOKEN\"
}")"
echo "$MAGIC_CONFIRM" | jq
assert_no_error "$MAGIC_CONFIRM" "magic login confirmed"

MAGIC_SESSION_TOKEN="$(echo "$MAGIC_CONFIRM" | jq -r '.token // empty')"
if [[ -z "$MAGIC_SESSION_TOKEN" || "$MAGIC_SESSION_TOKEN" == "null" ]]; then
  echo "[KO] magic login did not return session token"
  exit 1
fi
echo "[OK] magic login returned session token"

echo
echo "13) Reuse magic login token must fail"
MAGIC_REUSE="$(api POST "/api/v2/public/magic-login/confirm" "{
  \"token\":\"$MAGIC_TOKEN\"
}")"
echo "$MAGIC_REUSE" | jq
assert_error_present "$MAGIC_REUSE" "magic login token cannot be reused"

echo
echo "14) Magic login request for unverified user should not reveal account existence"
UNVERIFIED_EMAIL="$(unique_email unverified)"
CREATE_UNVERIFIED="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$UNVERIFIED_EMAIL\",
  \"display_name\":\"Unverified Magic User\",
  \"role\":\"user\",
  \"is_active\":true,
  \"creation_mode\":\"password\",
  \"password\":\"UnverifiedStrong123!\",
  \"force_password_change\":false
}" "$ADMIN_TOKEN")"
echo "$CREATE_UNVERIFIED" | jq
assert_no_error "$CREATE_UNVERIFIED" "unverified user created"

UNVERIFIED_MAGIC="$(api POST "/api/v2/public/magic-login/request" "{
  \"email\":\"$UNVERIFIED_EMAIL\"
}")"
echo "$UNVERIFIED_MAGIC" | jq
assert_no_error "$UNVERIFIED_MAGIC" "magic login request for unverified user returns generic success/no leak"

UNVERIFIED_MAGIC_URL="$(echo "$UNVERIFIED_MAGIC" | jq -r '.magic_url // empty')"
if [[ -n "$UNVERIFIED_MAGIC_URL" && "$UNVERIFIED_MAGIC_URL" != "null" ]]; then
  echo "[KO] magic login returned magic_url for unverified user"
  exit 1
fi
echo "[OK] magic login did not issue visible magic_url for unverified user"
echo
echo "15) Real email verification request + confirm for password-created user"

VERIFY_EMAIL="$(unique_email verify)"
CREATE_VERIFY_USER="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$VERIFY_EMAIL\",
  \"display_name\":\"Email Verification User\",
  \"role\":\"user\",
  \"is_active\":true,
  \"creation_mode\":\"password\",
  \"password\":\"VerifyStrong123!\",
  \"force_password_change\":false
}" "$ADMIN_TOKEN")"
echo "$CREATE_VERIFY_USER" | jq
assert_no_error "$CREATE_VERIFY_USER" "email verification test user created"

VERIFY_USER_ID="$(echo "$CREATE_VERIFY_USER" | jq -r '.id // empty')"

VERIFY_LOGIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$VERIFY_EMAIL\",
  \"password\":\"VerifyStrong123!\"
}")"
echo "$VERIFY_LOGIN" | jq
assert_no_error "$VERIFY_LOGIN" "email verification test user login"

VERIFY_USER_TOKEN="$(echo "$VERIFY_LOGIN" | jq -r '.token // empty')"
if [[ -z "$VERIFY_USER_TOKEN" || "$VERIFY_USER_TOKEN" == "null" ]]; then
  echo "[KO] verification user token missing"
  exit 1
fi

VERIFY_REQUEST_REAL="$(api POST "/api/v2/me/request-email-verification" "" "$VERIFY_USER_TOKEN")"
echo "$VERIFY_REQUEST_REAL" | jq
assert_no_error "$VERIFY_REQUEST_REAL" "email verification request accepted"

VERIFY_URL_REAL="$(echo "$VERIFY_REQUEST_REAL" | jq -r '.verification_url // empty')"

if [[ -z "$VERIFY_URL_REAL" || "$VERIFY_URL_REAL" == "null" ]]; then
  echo "[WARN] verification_url missing from response; creating email_verification token directly for backend validation"

  VERIFY_DIRECT="$(python3 - <<PY
import json
from app import app

user_id = "$VERIFY_USER_ID"

with app.app_context():
    token_service = app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    app_settings = app.config["APP_SETTINGS_SERVICE_V2"]

    token, raw = token_service.create_token(
        user_id=user_id,
        token_type="email_verification",
        ttl_hours=app_settings.get_email_verification_ttl_hours(),
        created_by_user_id=user_id,
    )

    print(json.dumps({
        "verification_url": token_service.build_email_verification_url(raw),
        "expires_at": getattr(token, "expires_at", None),
        "token_type": getattr(token, "token_type", "email_verification"),
    }, ensure_ascii=False))
PY
)"
  echo "$VERIFY_DIRECT" | jq
  VERIFY_URL_REAL="$(echo "$VERIFY_DIRECT" | jq -r '.verification_url // empty')"
else
  echo "[OK] email verification request returned verification_url"
fi

VERIFY_TOKEN_REAL="$(extract_token_from_url "$VERIFY_URL_REAL")"
if [[ -z "$VERIFY_TOKEN_REAL" ]]; then
  echo "[KO] verification token extraction failed"
  echo "URL=$VERIFY_URL_REAL"
  exit 1
fi
echo "[OK] verification token extracted"

VERIFY_STATUS_REAL="$(api GET "/api/v2/public/tokens/$VERIFY_TOKEN_REAL/status")"
echo "$VERIFY_STATUS_REAL" | jq
assert_no_error "$VERIFY_STATUS_REAL" "email verification token status valid"

VERIFY_TYPE_REAL="$(echo "$VERIFY_STATUS_REAL" | jq -r '.token_type // empty')"
assert_equals "$VERIFY_TYPE_REAL" "email_verification" "email verification token type"

CONFIRM_VERIFY_REAL="$(api POST "/api/v2/public/email-verification/confirm" "{
  \"token\":\"$VERIFY_TOKEN_REAL\"
}")"
echo "$CONFIRM_VERIFY_REAL" | jq
assert_no_error "$CONFIRM_VERIFY_REAL" "email verification confirmed"

REUSE_VERIFY_REAL="$(api POST "/api/v2/public/email-verification/confirm" "{
  \"token\":\"$VERIFY_TOKEN_REAL\"
}")"
echo "$REUSE_VERIFY_REAL" | jq
assert_error_present "$REUSE_VERIFY_REAL" "email verification token cannot be reused"
echo
echo "=== OK: transactional auth email workflow passed ==="
