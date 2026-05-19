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

echo "=== Link2NAS V2 admin timeouts test ==="

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
fi

echo
echo "4) Read default restart cooldowns"
DEFAULTS="$(api GET "/api/v2/admin/timeouts/restart-cooldowns" "" "$TOKEN")"
echo "$DEFAULTS" | jq
assert_no_error "$DEFAULTS" "restart cooldowns read"

echo
echo "5) Save restart cooldowns"
SAVE="$(api PUT "/api/v2/admin/timeouts/restart-cooldowns" "{
  \"default_seconds\": 11,
  \"realdebrid_seconds\": 61,
  \"alldebrid_seconds\": 9
}" "$TOKEN")"
echo "$SAVE" | jq
assert_no_error "$SAVE" "restart cooldowns saved"

assert_equals "$(echo "$SAVE" | jq -r '.default_seconds')" "11" "saved default_seconds"
assert_equals "$(echo "$SAVE" | jq -r '.realdebrid_seconds')" "61" "saved realdebrid_seconds"
assert_equals "$(echo "$SAVE" | jq -r '.alldebrid_seconds')" "9" "saved alldebrid_seconds"

echo
echo "6) Read restart cooldowns again"
READ="$(api GET "/api/v2/admin/timeouts/restart-cooldowns" "" "$TOKEN")"
echo "$READ" | jq
assert_no_error "$READ" "restart cooldowns read again"

assert_equals "$(echo "$READ" | jq -r '.default_seconds')" "11" "persisted default_seconds"
assert_equals "$(echo "$READ" | jq -r '.realdebrid_seconds')" "61" "persisted realdebrid_seconds"
assert_equals "$(echo "$READ" | jq -r '.alldebrid_seconds')" "9" "persisted alldebrid_seconds"

echo
echo "7) Invalid negative cooldown must fail"
INVALID="$(api PUT "/api/v2/admin/timeouts/restart-cooldowns" "{
  \"default_seconds\": -1
}" "$TOKEN")"
echo "$INVALID" | jq

ERROR="$(echo "$INVALID" | jq -r '.error // empty')"
if [[ "$ERROR" != "default_seconds must be >= 0" ]]; then
  echo "[KO] expected default_seconds validation error, got: $ERROR"
  exit 1
fi
echo "[OK] invalid cooldown rejected"

echo
echo "8) Restore defaults"
RESTORE="$(api PUT "/api/v2/admin/timeouts/restart-cooldowns" "{
  \"default_seconds\": 10,
  \"realdebrid_seconds\": 60,
  \"alldebrid_seconds\": 8
}" "$TOKEN")"
echo "$RESTORE" | jq
assert_no_error "$RESTORE" "restart cooldowns restored"

echo
echo "=== OK: admin timeouts workflow passed ==="
