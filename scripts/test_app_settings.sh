#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

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

echo "=== Link2NAS V2 app settings API test ==="
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
echo "3b) Reset security settings to defaults"
RESET_SECURITY="$(api PUT "/api/v2/admin/app-settings/security" "{
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
}" "$TOKEN")"
echo "$RESET_SECURITY" | jq
assert_no_error "$RESET_SECURITY" "security settings reset to defaults"

echo
echo "3c) Reset cleanup settings to defaults"
RESET_CLEANUP="$(api PUT "/api/v2/admin/app-settings/cleanup" "{
  \"retention\": {
    \"torrent_tmp_days\": 7,
    \"completed_jobs_days\": 30,
    \"failed_jobs_days\": 30,
    \"cancelled_jobs_days\": 15,
    \"expired_tokens_days\": 7
  }
}" "$TOKEN")"
echo "$RESET_CLEANUP" | jq
assert_no_error "$RESET_CLEANUP" "cleanup settings reset to defaults"

echo
echo "4) Read default security settings"
SECURITY_DEFAULT="$(api GET "/api/v2/admin/app-settings/security" "" "$TOKEN")"
echo "$SECURITY_DEFAULT" | jq
assert_no_error "$SECURITY_DEFAULT" "default security settings read"

assert_equals "$(echo "$SECURITY_DEFAULT" | jq -r '.token_ttl.invitation_ttl_hours')" "48" "default invitation_ttl_hours"
assert_equals "$(echo "$SECURITY_DEFAULT" | jq -r '.token_ttl.password_reset_ttl_hours')" "2" "default password_reset_ttl_hours"
assert_equals "$(echo "$SECURITY_DEFAULT" | jq -r '.token_ttl.magic_login_ttl_minutes')" "15" "default magic_login_ttl_minutes"
assert_equals "$(echo "$SECURITY_DEFAULT" | jq -r '.token_ttl.email_verification_ttl_hours')" "24" "default email_verification_ttl_hours"
assert_equals "$(echo "$SECURITY_DEFAULT" | jq -r '.token_ttl.session_inactivity_minutes')" "30" "default session_inactivity_minutes"
assert_equals "$(echo "$SECURITY_DEFAULT" | jq -r '.password_policy.min_length')" "10" "default password min_length"
echo
echo "5) Save security settings"
SECURITY_SAVE="$(api PUT "/api/v2/admin/app-settings/security" "{
  \"token_ttl\": {
    \"invitation_ttl_hours\": 72,
    \"password_reset_ttl_hours\": 3,
    \"magic_login_ttl_minutes\": 20,
    \"email_verification_ttl_hours\": 48,
    \"session_inactivity_minutes\": 45
  },
  \"password_policy\": {
    \"min_length\": 12,
    \"require_uppercase\": true,
    \"require_lowercase\": true,
    \"require_number\": true,
    \"require_special\": false
  }
}" "$TOKEN")"
echo "$SECURITY_SAVE" | jq
assert_no_error "$SECURITY_SAVE" "security settings saved"

assert_equals "$(echo "$SECURITY_SAVE" | jq -r '.token_ttl.magic_login_ttl_minutes')" "20" "saved magic_login_ttl_minutes"
assert_equals "$(echo "$SECURITY_SAVE" | jq -r '.password_policy.min_length')" "12" "saved password min_length"
assert_equals "$(echo "$SECURITY_SAVE" | jq -r '.password_policy.require_number')" "true" "saved require_number"

echo
echo "6) Read security settings again"
SECURITY_READ="$(api GET "/api/v2/admin/app-settings/security" "" "$TOKEN")"
echo "$SECURITY_READ" | jq
assert_no_error "$SECURITY_READ" "security settings read again"

assert_equals "$(echo "$SECURITY_READ" | jq -r '.token_ttl.invitation_ttl_hours')" "72" "persisted invitation_ttl_hours"
assert_equals "$(echo "$SECURITY_READ" | jq -r '.token_ttl.magic_login_ttl_minutes')" "20" "persisted magic_login_ttl_minutes"
assert_equals "$(echo "$SECURITY_READ" | jq -r '.password_policy.min_length')" "12" "persisted password min_length"

echo
echo "7) Invalid security setting must fail"
SECURITY_INVALID="$(api PUT "/api/v2/admin/app-settings/security" "{
  \"token_ttl\": {
    \"magic_login_ttl_minutes\": 1
  }
}" "$TOKEN")"
echo "$SECURITY_INVALID" | jq

INVALID_ERROR="$(echo "$SECURITY_INVALID" | jq -r '.error // empty')"
if [[ "$INVALID_ERROR" != "magic_login_ttl_minutes must be >= 5" ]]; then
  echo "[KO] expected invalid magic login TTL error, got: $INVALID_ERROR"
  exit 1
fi
echo "[OK] invalid magic login TTL rejected"

echo
echo "8) Read default cleanup settings"
CLEANUP_DEFAULT="$(api GET "/api/v2/admin/app-settings/cleanup" "" "$TOKEN")"
echo "$CLEANUP_DEFAULT" | jq
assert_no_error "$CLEANUP_DEFAULT" "default cleanup settings read"

assert_equals "$(echo "$CLEANUP_DEFAULT" | jq -r '.retention.torrent_tmp_days')" "7" "default torrent_tmp_days"
assert_equals "$(echo "$CLEANUP_DEFAULT" | jq -r '.retention.completed_jobs_days')" "30" "default completed_jobs_days"
assert_equals "$(echo "$CLEANUP_DEFAULT" | jq -r '.retention.failed_jobs_days')" "30" "default failed_jobs_days"
assert_equals "$(echo "$CLEANUP_DEFAULT" | jq -r '.retention.cancelled_jobs_days')" "15" "default cancelled_jobs_days"
assert_equals "$(echo "$CLEANUP_DEFAULT" | jq -r '.retention.expired_tokens_days')" "7" "default expired_tokens_days"

echo
echo "9) Save cleanup settings"
CLEANUP_SAVE="$(api PUT "/api/v2/admin/app-settings/cleanup" "{
  \"retention\": {
    \"torrent_tmp_days\": 10,
    \"completed_jobs_days\": 40,
    \"failed_jobs_days\": 50,
    \"cancelled_jobs_days\": 20,
    \"expired_tokens_days\": 8
  }
}" "$TOKEN")"
echo "$CLEANUP_SAVE" | jq
assert_no_error "$CLEANUP_SAVE" "cleanup settings saved"

assert_equals "$(echo "$CLEANUP_SAVE" | jq -r '.retention.torrent_tmp_days')" "10" "saved torrent_tmp_days"
assert_equals "$(echo "$CLEANUP_SAVE" | jq -r '.retention.completed_jobs_days')" "40" "saved completed_jobs_days"
assert_equals "$(echo "$CLEANUP_SAVE" | jq -r '.retention.expired_tokens_days')" "8" "saved expired_tokens_days"

echo
echo "10) Read cleanup settings again"
CLEANUP_READ="$(api GET "/api/v2/admin/app-settings/cleanup" "" "$TOKEN")"
echo "$CLEANUP_READ" | jq
assert_no_error "$CLEANUP_READ" "cleanup settings read again"

assert_equals "$(echo "$CLEANUP_READ" | jq -r '.retention.torrent_tmp_days')" "10" "persisted torrent_tmp_days"
assert_equals "$(echo "$CLEANUP_READ" | jq -r '.retention.completed_jobs_days')" "40" "persisted completed_jobs_days"

echo
echo "=== OK: app settings API workflow passed ==="
