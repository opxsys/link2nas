#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
EXPECTED_EMAIL="${EXPECTED_EMAIL:-}"
EXPECTED_DISPLAY_NAME="${EXPECTED_DISPLAY_NAME:-}"

echo "[TEST] Link2NAS single-user mode"
echo "[TEST] BASE_URL=$BASE_URL"
echo

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[OK] $*"
}

require_status() {
  local expected="$1"
  local method="$2"
  local url="$3"
  shift 3

  local status
  status="$(curl -s -o /tmp/link2nas_test_body.json -w "%{http_code}" -X "$method" "$url" "$@")"

  if [[ "$status" != "$expected" ]]; then
    echo "[DEBUG] Body:"
    cat /tmp/link2nas_test_body.json || true
    echo
    fail "$method $url expected HTTP $expected, got HTTP $status"
  fi

  pass "$method $url -> HTTP $status"
}

echo "[STEP] /me without token must work"
ME_BODY="$(curl -s "$BASE_URL/api/v2/me")"
echo "$ME_BODY" | jq .

SINGLE_USER_MODE="$(echo "$ME_BODY" | jq -r '.single_user_mode')"
ROLE="$(echo "$ME_BODY" | jq -r '.role')"
USER_ID="$(echo "$ME_BODY" | jq -r '.id')"
EMAIL="$(echo "$ME_BODY" | jq -r '.email')"
EMAIL_VERIFIED="$(echo "$ME_BODY" | jq -r '.email_verified')"

[[ "$SINGLE_USER_MODE" == "true" ]] || fail "expected single_user_mode=true, got $SINGLE_USER_MODE"
[[ "$ROLE" == "super_admin" ]] || fail "expected role=super_admin, got $ROLE"
[[ "$USER_ID" == "00000000-0000-4000-8000-000000000001" ]] || fail "unexpected single user id: $USER_ID"
[[ "$EMAIL_VERIFIED" == "true" ]] || fail "expected email_verified=true, got $EMAIL_VERIFIED"

if [[ -n "$EXPECTED_EMAIL" ]]; then
  [[ "$EMAIL" == "$EXPECTED_EMAIL" ]] || fail "expected email=$EXPECTED_EMAIL, got $EMAIL"
fi

if [[ -n "$EXPECTED_DISPLAY_NAME" ]]; then
  DISPLAY_NAME="$(echo "$ME_BODY" | jq -r '.display_name')"
  [[ "$DISPLAY_NAME" == "$EXPECTED_DISPLAY_NAME" ]] || fail "expected display_name=$EXPECTED_DISPLAY_NAME, got $DISPLAY_NAME"
fi

pass "/me returns internal single-user super_admin"

echo
echo "[STEP] admin users must be blocked in single-user"
require_status "403" GET "$BASE_URL/api/v2/admin/users"

echo
echo "[STEP] password change must be blocked in single-user"
require_status "403" POST "$BASE_URL/api/v2/me/password" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"x","new_password":"y"}'

echo
echo "[STEP] admin technical endpoints must be available without token"
require_status "200" GET "$BASE_URL/api/v2/admin/maintenance/status"
require_status "200" GET "$BASE_URL/api/v2/admin/smtp-settings"
require_status "200" GET "$BASE_URL/api/v2/admin/app-settings/security"
require_status "200" GET "$BASE_URL/api/v2/admin/app-settings/cleanup"
require_status "200" GET "$BASE_URL/api/v2/admin/app-settings/runtime"
require_status "200" GET "$BASE_URL/api/v2/admin/timeouts/restart-cooldowns"

echo
echo "[STEP] user settings endpoints must be available without token"
require_status "200" GET "$BASE_URL/api/v2/providers"
require_status "200" GET "$BASE_URL/api/v2/destinations"
require_status "200" GET "$BASE_URL/api/v2/me/api-keys"
require_status "200" GET "$BASE_URL/api/v2/me/integration-settings"
require_status "200" GET "$BASE_URL/api/v2/notifications/configs"
require_status "200" GET "$BASE_URL/api/v2/notifications/rules"

echo
echo "[STEP] qBittorrent compat app version without API key should still be rejected or controlled"
STATUS="$(curl -s -o /tmp/link2nas_qbit_body.json -w "%{http_code}" "$BASE_URL/qbittorrent/api/v2/app/version" || true)"

if [[ "$STATUS" == "200" ]]; then
  echo "[WARN] qBittorrent app/version returned 200 without API key. Check if this is intended."
else
  pass "qBittorrent app/version without API key did not open freely -> HTTP $STATUS"
fi

echo
echo "[SUCCESS] Single-user smoke test passed"
