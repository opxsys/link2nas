#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"
USER_EMAIL="${USER_EMAIL:-verify-user-$(date +%s)-$$@test.local}"
USER_PASSWORD="${USER_PASSWORD:-VerifyPass123!}"

api() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local token="${4:-}"

  if [[ -n "$data" && -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$data" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token"
  else
    curl -sS -X "$method" "$BASE_URL$path"
  fi
}

assert_no_error() {
  local json="$1"
  local label="$2"
  local error
  error="$(echo "$json" | jq -r '.error // empty')"

  if [[ -n "$error" ]]; then
    echo "[KO] $label: $error"
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
    echo "[KO] $label: expected '$expected', got '$actual'"
    exit 1
  fi

  echo "[OK] $label"
}

extract_token_from_url() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse, parse_qs

url = sys.argv[1]
query = urlparse(url).query
print(parse_qs(query).get("token", [""])[0])
PY
}

echo "=== Link2NAS V2 email verification workflow test ==="
echo "BASE_URL=$BASE_URL"
echo "USER_EMAIL=$USER_EMAIL"

command -v curl >/dev/null || { echo "[KO] curl missing"; exit 1; }
command -v jq >/dev/null || { echo "[KO] jq missing"; exit 1; }

echo
echo "1) Setup status"
SETUP_STATUS="$(api GET "/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo
  echo "2) Create first admin"
  CREATE_ADMIN="$(api POST "/api/v2/setup/first-admin" "{
    \"email\":\"$ADMIN_EMAIL\",
    \"display_name\":\"Admin\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  echo "$CREATE_ADMIN" | jq
  assert_no_error "$CREATE_ADMIN" "first admin created"
else
  echo "[INFO] Setup already completed"
fi

echo
echo "3) Login admin"
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  ADMIN_TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN_ADMIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
  echo "$LOGIN_ADMIN" | jq
  assert_no_error "$LOGIN_ADMIN" "admin login"
  ADMIN_TOKEN="$(echo "$LOGIN_ADMIN" | jq -r '.token // empty')"
fi

echo
echo "4) Ensure default password policy"
SECURITY_SAVE="$(api PUT "/api/v2/admin/app-settings/security" "{
  \"token_ttl\": {
    \"invitation_ttl_hours\": 48,
    \"password_reset_ttl_hours\": 2,
    \"magic_login_ttl_minutes\": 15,
    \"email_verification_ttl_hours\": 24,
    \"session_inactivity_minutes\": 30
  },
  \"password_policy\": {
    \"min_length\": 10,
    \"require_uppercase\": false,
    \"require_lowercase\": false,
    \"require_number\": false,
    \"require_special\": false
  }
}" "$ADMIN_TOKEN")"
echo "$SECURITY_SAVE" | jq
assert_no_error "$SECURITY_SAVE" "security defaults saved"

echo
echo "5) Create normal user with unverified email"
CREATE_USER="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$USER_EMAIL\",
  \"display_name\":\"Verify User\",
  \"creation_mode\":\"password\",
  \"password\":\"$USER_PASSWORD\",
  \"force_password_change\": false,
  \"email_verified\": false
}" "$ADMIN_TOKEN")"
echo "$CREATE_USER" | jq
assert_no_error "$CREATE_USER" "user created"
assert_equals "$(echo "$CREATE_USER" | jq -r '.email_verified')" "false" "email initially unverified"

echo
echo "6) Login user"
LOGIN_USER="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$USER_EMAIL\",
  \"password\":\"$USER_PASSWORD\"
}")"
echo "$LOGIN_USER" | jq
assert_no_error "$LOGIN_USER" "user login"

USER_TOKEN="$(echo "$LOGIN_USER" | jq -r '.token // empty')"

echo
echo "7) Request email verification"
VERIFY_REQUEST="$(api POST "/api/v2/me/request-email-verification" "" "$USER_TOKEN")"
echo "$VERIFY_REQUEST" | jq
assert_no_error "$VERIFY_REQUEST" "verification email requested"

VERIFY_URL="$(echo "$VERIFY_REQUEST" | jq -r '.verification_url // empty')"
if [[ -z "$VERIFY_URL" || "$VERIFY_URL" == "null" ]]; then
  echo "[KO] verification_url missing"
  exit 1
fi
echo "[OK] verification_url present"

VERIFY_TOKEN="$(extract_token_from_url "$VERIFY_URL")"
if [[ -z "$VERIFY_TOKEN" ]]; then
  echo "[KO] verification token extraction failed"
  exit 1
fi
echo "[OK] verification token extracted"

echo
echo "8) Confirm email verification"
VERIFY_CONFIRM="$(api POST "/api/v2/public/email-verification/confirm" "{
  \"token\":\"$VERIFY_TOKEN\"
}")"
echo "$VERIFY_CONFIRM" | jq
assert_no_error "$VERIFY_CONFIRM" "email verification confirmed"

echo
echo "9) Reuse token must fail"
VERIFY_REUSE="$(api POST "/api/v2/public/email-verification/confirm" "{
  \"token\":\"$VERIFY_TOKEN\"
}")"
echo "$VERIFY_REUSE" | jq

REUSE_ERROR="$(echo "$VERIFY_REUSE" | jq -r '.error // empty')"
if [[ "$REUSE_ERROR" != "Token already used" ]]; then
  echo "[KO] expected token already used, got: $REUSE_ERROR"
  exit 1
fi
echo "[OK] verification token cannot be reused"

echo
echo "10) /me shows email verified"
ME="$(api GET "/api/v2/me" "" "$USER_TOKEN")"
echo "$ME" | jq
assert_no_error "$ME" "me read"
assert_equals "$(echo "$ME" | jq -r '.email_verified')" "true" "email verified"

echo
echo "=== OK: email verification workflow passed ==="

