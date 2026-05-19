#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
TOKEN="${ADMIN_API_KEY:-${TOKEN:-}}"

echo "[TEST] Link2NAS multi-user mode"
echo "[TEST] BASE_URL=$BASE_URL"
echo

fail() {
  echo "[FAIL] $1"
  exit 1
}

pass() {
  echo "[OK] $1"
}

expect_status() {
  local label="$1"
  local expected="$2"
  local method="${3:-GET}"
  local url="$4"
  local token="${5:-}"
  local body="${6:-}"

  echo "[TEST] $label"

  headers=()
  if [[ -n "$token" ]]; then
    headers=(-H "X-Api-Key: $token")
  fi

  if [[ "$method" == "POST" || "$method" == "PUT" || "$method" == "PATCH" ]]; then
    status="$(curl -s -o /tmp/link2nas_test_body.json -w "%{http_code}" \
      -X "$method" \
      -H "Content-Type: application/json" \
      "${headers[@]}" \
      -d "$body" \
      "$url")"
  else
    status="$(curl -s -o /tmp/link2nas_test_body.json -w "%{http_code}" \
      -X "$method" \
      "${headers[@]}" \
      "$url")"
  fi

  cat /tmp/link2nas_test_body.json
  echo

  if [[ "$status" != "$expected" ]]; then
    fail "$label expected HTTP $expected, got HTTP $status"
  fi

  pass "$label returned HTTP $expected"
  echo
}

expect_json_field_with_token() {
  local label="$1"
  local jq_expr="$2"
  local expected="$3"
  local url="$4"
  local token="$5"

  echo "[TEST] $label"

  body="$(curl -s -H "X-Api-Key: $token" "$url")"
  echo "$body" | jq

  value="$(echo "$body" | jq -r "$jq_expr")"

  if [[ "$value" != "$expected" ]]; then
    fail "$label expected '$expected', got '$value'"
  fi

  pass "$label"
  echo
}

echo "[INFO] This script expects LINK2NAS_SINGLE_USER_MODE=false on the running server."
echo

expect_status "GET /api/v2/me without token is rejected" \
  "401" \
  "GET" \
  "$BASE_URL/api/v2/me"

if [[ -z "$TOKEN" ]]; then
  echo "[INFO] TOKEN is not set. Skipping authenticated multi-user checks."
  echo "[INFO] Run like:"
  echo "       TOKEN=l2n_xxx ./scripts/test_multi_user_mode.sh"
  exit 0
fi

expect_json_field_with_token "GET /api/v2/me with token exposes multi-user mode" \
  '.single_user_mode | tostring' \
  'false' \
  "$BASE_URL/api/v2/me" \
  "$TOKEN"

expect_json_field_with_token "GET /api/v2/me with token has super_admin role" \
  '.role' \
  'super_admin' \
  "$BASE_URL/api/v2/me" \
  "$TOKEN"

expect_status "Admin users is allowed in multi-user mode" \
  "200" \
  "GET" \
  "$BASE_URL/api/v2/admin/users" \
  "$TOKEN"

expect_status "Admin maintenance is allowed in multi-user mode" \
  "200" \
  "GET" \
  "$BASE_URL/api/v2/admin/maintenance/status" \
  "$TOKEN"

expect_status "Admin SMTP is allowed in multi-user mode" \
  "200" \
  "GET" \
  "$BASE_URL/api/v2/admin/smtp-settings" \
  "$TOKEN"

expect_status "Admin security settings are allowed in multi-user mode" \
  "200" \
  "GET" \
  "$BASE_URL/api/v2/admin/app-settings/security" \
  "$TOKEN"

expect_status "Admin cleanup settings are allowed in multi-user mode" \
  "200" \
  "GET" \
  "$BASE_URL/api/v2/admin/app-settings/cleanup" \
  "$TOKEN"

expect_status "Admin runtime settings are allowed in multi-user mode" \
  "200" \
  "GET" \
  "$BASE_URL/api/v2/admin/app-settings/runtime" \
  "$TOKEN"

expect_status "Admin restart cooldowns are allowed in multi-user mode" \
  "200" \
  "GET" \
  "$BASE_URL/api/v2/admin/timeouts/restart-cooldowns" \
  "$TOKEN"

echo "[SUCCESS] Multi-user mode smoke test passed."
