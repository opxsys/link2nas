#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%s)-$$"
WEAK_USER_EMAIL="weak-user-${RUN_ID}@test.local"
STRONG_USER_EMAIL="strong-user-${RUN_ID}@test.local"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[KO] Missing command: $1"
    exit 1
  }
}

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

assert_error_contains() {
  local json="$1"
  local expected="$2"
  local label="$3"
  local error
  error="$(echo "$json" | jq -r '.error // empty')"

  if [[ "$error" != *"$expected"* ]]; then
    echo "[KO] $label: expected error containing '$expected', got '$error'"
    echo "$json" | jq
    exit 1
  fi

  echo "[OK] $label"
}

echo "=== Link2NAS V2 app settings auth policy test ==="
echo "BASE_URL=$BASE_URL"

need_cmd curl
need_cmd jq

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
  TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN_ADMIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
  echo "$LOGIN_ADMIN" | jq
  assert_no_error "$LOGIN_ADMIN" "admin login"
  TOKEN="$(echo "$LOGIN_ADMIN" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "[KO] admin token missing"
    exit 1
  fi
  echo "[OK] admin token received"
fi

echo
echo "4) Set strict password policy and short token TTLs"
SECURITY_SAVE="$(api PUT "/api/v2/admin/app-settings/security" "{
  \"token_ttl\": {
    \"invitation_ttl_hours\": 1,
    \"password_reset_ttl_hours\": 1,
    \"magic_login_ttl_minutes\": 5,
    \"email_verification_ttl_hours\": 24,
    \"session_inactivity_minutes\": 30
  },
  \"password_policy\": {
    \"min_length\": 12,
    \"require_uppercase\": true,
    \"require_lowercase\": true,
    \"require_number\": true,
    \"require_special\": true
  }
}" "$TOKEN")"
echo "$SECURITY_SAVE" | jq
assert_no_error "$SECURITY_SAVE" "strict security settings saved"

echo
echo "5) Create user with weak password must fail"
WEAK_USER="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$WEAK_USER_EMAIL\",
  \"display_name\":\"Weak User\",
  \"creation_mode\":\"password\",
  \"password\":\"weakpass\",
  \"force_password_change\": true
}" "$TOKEN")"
echo "$WEAK_USER" | jq
assert_error_contains "$WEAK_USER" "at least 12" "weak user password rejected"

echo
echo "6) Create user with strong password must pass"
STRONG_USER="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$STRONG_USER_EMAIL\",
  \"display_name\":\"Strong User\",
  \"creation_mode\":\"password\",
  \"password\":\"StrongPass123!\",
  \"force_password_change\": true
}" "$TOKEN")"
echo "$STRONG_USER" | jq
assert_no_error "$STRONG_USER" "strong user password accepted"

USER_ID="$(echo "$STRONG_USER" | jq -r '.id // empty')"
if [[ -z "$USER_ID" || "$USER_ID" == "null" ]]; then
  echo "[KO] user id missing"
  exit 1
fi

echo
echo "7) Manual admin reset weak password must fail"
WEAK_RESET="$(api POST "/api/v2/admin/users/$USER_ID/reset-password" "{
  \"password\":\"weakpass\"
}" "$TOKEN")"
echo "$WEAK_RESET" | jq
assert_error_contains "$WEAK_RESET" "at least 12" "weak reset password rejected"

echo
echo "8) Manual admin reset strong password must pass"
STRONG_RESET="$(api POST "/api/v2/admin/users/$USER_ID/reset-password" "{
  \"password\":\"AnotherPass123!\"
}" "$TOKEN")"
echo "$STRONG_RESET" | jq
assert_no_error "$STRONG_RESET" "strong reset password accepted"

echo
echo "9) Create invitation token should use configured TTL"
INVITATION="$(api POST "/api/v2/admin/users/$USER_ID/invitation" "" "$TOKEN")"
echo "$INVITATION" | jq
assert_no_error "$INVITATION" "invitation created"

INV_EXPIRES="$(echo "$INVITATION" | jq -r '.expires_at // empty')"
if [[ -z "$INV_EXPIRES" || "$INV_EXPIRES" == "null" ]]; then
  echo "[KO] invitation expires_at missing"
  exit 1
fi
echo "[OK] invitation expires_at present: $INV_EXPIRES"

echo
echo "10) Create password reset token should use configured TTL"
RESET_LINK="$(api POST "/api/v2/admin/users/$USER_ID/password-reset-link" "" "$TOKEN")"
echo "$RESET_LINK" | jq
assert_no_error "$RESET_LINK" "password reset link created"

RESET_EXPIRES="$(echo "$RESET_LINK" | jq -r '.expires_at // empty')"
if [[ -z "$RESET_EXPIRES" || "$RESET_EXPIRES" == "null" ]]; then
  echo "[KO] reset expires_at missing"
  exit 1
fi
echo "[OK] reset expires_at present: $RESET_EXPIRES"

echo
echo "=== OK: app settings auth policy workflow passed ==="
