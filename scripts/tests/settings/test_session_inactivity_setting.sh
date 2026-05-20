#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

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

# ---- state ------------------------------------------------------------------

TOKEN="${TOKEN:-}"
SECURITY_MODIFIED=false

cleanup() {
  local exit_code=$?
  if [[ "$SECURITY_MODIFIED" == "true" && -n "$TOKEN" ]]; then
    echo
    echo "--- Cleanup: restoring session_inactivity_minutes to 30 ---"
    api PUT "/api/v2/admin/app-settings/security" "{
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
    }" "$TOKEN" >/dev/null 2>&1 || true
    echo "[INFO] Security settings restored."
  fi
}
trap cleanup EXIT

echo "=== Link2NAS V2 session inactivity setting test ==="

command -v curl >/dev/null || { echo "[KO] curl missing"; exit 1; }
command -v jq >/dev/null || { echo "[KO] jq missing"; exit 1; }

if [[ "$ADMIN_EMAIL" == "admin@test.local" || "$ADMIN_PASSWORD" == "AdminPassword123!" || -z "$ADMIN_PASSWORD" ]]; then
  echo "[INFO] This script requires valid ADMIN_EMAIL/ADMIN_PASSWORD for the final login assertion."
fi

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
  assert_equals "$(echo "$LOGIN_ADMIN" | jq -r '.user.session_inactivity_minutes')" "30" "default session_inactivity_minutes in login"
fi

echo
echo "4) Update session inactivity to 45"
SECURITY_SAVE="$(api PUT "/api/v2/admin/app-settings/security" "{
  \"token_ttl\": {
    \"invitation_ttl_hours\": 48,
    \"password_reset_ttl_hours\": 2,
    \"magic_login_ttl_minutes\": 15,
    \"email_verification_ttl_hours\": 24,
    \"session_inactivity_minutes\": 45
  },
  \"password_policy\": {
    \"min_length\": 10,
    \"require_uppercase\": false,
    \"require_lowercase\": false,
    \"require_number\": false,
    \"require_special\": false
  }
}" "$TOKEN")"
echo "$SECURITY_SAVE" | jq
assert_no_error "$SECURITY_SAVE" "security settings saved"
SECURITY_MODIFIED=true

echo
echo "5) Login admin again"
LOGIN_ADMIN_2="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
echo "$LOGIN_ADMIN_2" | jq
assert_no_error "$LOGIN_ADMIN_2" "admin login again"

TOKEN_2="$(echo "$LOGIN_ADMIN_2" | jq -r '.token // empty')"
assert_equals "$(echo "$LOGIN_ADMIN_2" | jq -r '.user.session_inactivity_minutes')" "45" "updated session_inactivity_minutes in login"

echo
echo "6) /me returns session inactivity"
ME="$(api GET "/api/v2/me" "" "$TOKEN_2")"
echo "$ME" | jq
assert_no_error "$ME" "me read"
assert_equals "$(echo "$ME" | jq -r '.session_inactivity_minutes')" "45" "updated session_inactivity_minutes in /me"


echo
echo "7) Restore session inactivity to 30"
RESTORE_SECURITY="$(api PUT "/api/v2/admin/app-settings/security" "{
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
}" "$TOKEN_2")"
echo "$RESTORE_SECURITY" | jq
assert_no_error "$RESTORE_SECURITY" "security settings restored"
SECURITY_MODIFIED=false


echo
echo "=== OK: session inactivity setting workflow passed ==="
