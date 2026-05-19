#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

TOKEN=""
TEST_USER_ID=""
_TMPBODY=""
TEST_EMAIL="check-admin-users-$(date +%s)@test.local"

# -- helpers --

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}

api() {
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  local args=(-sS -X "$method" "$BASE_URL$path")
  [[ -n "$token" ]] && args+=(-H "X-Api-Key: $token")
  [[ -n "$data" ]] && args+=(-H "Content-Type: application/json" -d "$data")
  curl "${args[@]}"
}

api_status() {
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  local args=(-s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path")
  [[ -n "$token" ]] && args+=(-H "X-Api-Key: $token")
  [[ -n "$data" ]] && args+=(-H "Content-Type: application/json" -d "$data")
  curl "${args[@]}"
}

# Writes body to $_TMPBODY; returns HTTP status code on stdout.
# Safe with multi-line or pretty-printed JSON.
api_full() {
  [[ -n "$_TMPBODY" ]] && rm -f "$_TMPBODY" || true
  _TMPBODY="$(mktemp)"
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  local args=(-sS -X "$method" "$BASE_URL$path" -o "$_TMPBODY" -w "%{http_code}")
  [[ -n "$token" ]] && args+=(-H "X-Api-Key: $token")
  [[ -n "$data" ]] && args+=(-H "Content-Type: application/json" -d "$data")
  curl "${args[@]}"
}

ok()   { echo "[OK] $*"; }
fail() { echo "[KO] $*"; exit 1; }

assert_http() {
  local expected="$1" actual="$2" label="$3"
  [[ "$actual" == "$expected" ]] \
    && ok "$label => HTTP $actual" \
    || fail "$label: expected HTTP $expected, got HTTP $actual"
}

assert_no_error() {
  local json="$1" label="$2"
  local err
  err="$(echo "$json" | jq -r '.error // empty')"
  if [[ -n "$err" ]]; then
    echo "[KO] $label: $err"
    echo "$json" | jq . 2>/dev/null || true
    exit 1
  fi
  ok "$label"
}

assert_field() {
  local json="$1" field="$2" label="$3"
  local val
  val="$(echo "$json" | jq -r "$field // empty")"
  if [[ -z "$val" || "$val" == "null" ]]; then
    echo "[KO] $label: '$field' missing or null"
    echo "$json" | jq . 2>/dev/null || true
    exit 1
  fi
  ok "$label"
}

assert_json_str() {
  local json="$1" field="$2" expected="$3" label="$4"
  local val
  val="$(echo "$json" | jq -r "$field // empty")"
  [[ "$val" == "$expected" ]] \
    && ok "$label" \
    || fail "$label: expected '$expected', got '$val'"
}

# -- cleanup --

cleanup() {
  [[ -n "$_TMPBODY" ]] && rm -f "$_TMPBODY" || true
  if [[ -n "$TEST_USER_ID" ]]; then
    echo "[cleanup] Deleting test user $TEST_USER_ID ..."
    api DELETE "/api/v2/admin/users/$TEST_USER_ID" "" "${TOKEN:-}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ============================================================

echo "=== check_admin_users_routes ==="
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
echo

need_cmd curl
need_cmd jq

# --- Preflight ---
echo "--- Preflight: app reachability"
REACH="$(api_status GET "/api/v2/me")"
if [[ "$REACH" != "200" && "$REACH" != "401" && "$REACH" != "403" ]]; then
  fail "App not reachable at $BASE_URL (HTTP $REACH)"
fi
ok "App reachable (HTTP $REACH)"
echo

# --- Step 1: Login admin ---
echo "--- Step 1: Login admin"
LOGIN="$(api POST "/api/v2/auth/login" \
  "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
assert_no_error "$LOGIN" "admin login"
TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || fail "admin token missing in login response"
ok "admin token received (${TOKEN:0:8}****)"
echo

# --- Step 2: GET /me ---
echo "--- Step 2: GET /api/v2/me"
STATUS="$(api_status GET "/api/v2/me" "" "$TOKEN")"
assert_http 200 "$STATUS" "GET /api/v2/me"
ME="$(api GET "/api/v2/me" "" "$TOKEN")"
assert_no_error "$ME" "GET /me body"
assert_field "$ME" ".id" "/me has .id"
assert_json_str "$ME" ".role" "super_admin" "/me role=super_admin"
echo

# --- Step 3: List users ---
echo "--- Step 3: GET /api/v2/admin/users"
STATUS="$(api_status GET "/api/v2/admin/users" "" "$TOKEN")"
assert_http 200 "$STATUS" "GET /api/v2/admin/users"
USERS="$(api GET "/api/v2/admin/users" "" "$TOKEN")"
ok "list users => $(echo "$USERS" | jq 'length') user(s)"
echo

# --- Step 4: Create test user ---
echo "--- Step 4: Create test user ($TEST_EMAIL)"
CREATE_PAYLOAD="{\"email\":\"$TEST_EMAIL\",\"password\":\"TestPass123!\",\"creation_mode\":\"password\",\"is_super_admin\":false,\"display_name\":\"Check User\"}"
CREATE_STATUS="$(api_full POST "/api/v2/admin/users" "$CREATE_PAYLOAD" "$TOKEN")"
CREATE_BODY="$(cat "$_TMPBODY")"
assert_http 201 "$CREATE_STATUS" "POST /admin/users"
assert_no_error "$CREATE_BODY" "create user body"
TEST_USER_ID="$(echo "$CREATE_BODY" | jq -r '.id // empty')"
[[ -n "$TEST_USER_ID" && "$TEST_USER_ID" != "null" ]] || fail "created user .id missing"
ok "test user created id=$TEST_USER_ID"
echo

# --- Step 5: PATCH display_name ---
echo "--- Step 5: PATCH /api/v2/admin/users/$TEST_USER_ID"
PATCH_STATUS="$(api_full PATCH "/api/v2/admin/users/$TEST_USER_ID" \
  "{\"display_name\":\"Patched Name\"}" "$TOKEN")"
PATCH_BODY="$(cat "$_TMPBODY")"
assert_http 200 "$PATCH_STATUS" "PATCH /admin/users/<id>"
assert_no_error "$PATCH_BODY" "patch body"
assert_json_str "$PATCH_BODY" ".display_name" "Patched Name" "display_name updated"
echo

# --- Step 6: Disable ---
echo "--- Step 6: POST /api/v2/admin/users/$TEST_USER_ID/disable"
DISABLE_STATUS="$(api_full POST "/api/v2/admin/users/$TEST_USER_ID/disable" "" "$TOKEN")"
DISABLE_BODY="$(cat "$_TMPBODY")"
assert_http 200 "$DISABLE_STATUS" "POST /disable"
assert_no_error "$DISABLE_BODY" "disable body"
assert_json_str "$DISABLE_BODY" ".is_active | tostring" "false" "is_active=false after disable"
echo

# --- Step 7: Enable ---
echo "--- Step 7: POST /api/v2/admin/users/$TEST_USER_ID/enable"
ENABLE_STATUS="$(api_full POST "/api/v2/admin/users/$TEST_USER_ID/enable" "" "$TOKEN")"
ENABLE_BODY="$(cat "$_TMPBODY")"
assert_http 200 "$ENABLE_STATUS" "POST /enable"
assert_no_error "$ENABLE_BODY" "enable body"
assert_json_str "$ENABLE_BODY" ".is_active | tostring" "true" "is_active=true after enable"
echo

# --- Step 8: Verify email ---
echo "--- Step 8: POST /api/v2/admin/users/$TEST_USER_ID/verify-email"
VERIFY_STATUS="$(api_full POST "/api/v2/admin/users/$TEST_USER_ID/verify-email" "" "$TOKEN")"
VERIFY_BODY="$(cat "$_TMPBODY")"
assert_http 200 "$VERIFY_STATUS" "POST /verify-email"
assert_no_error "$VERIFY_BODY" "verify-email body"
assert_json_str "$VERIFY_BODY" ".email_verified | tostring" "true" "email_verified=true"
echo

# --- Step 9: Password reset link ---
echo "--- Step 9: POST /api/v2/admin/users/$TEST_USER_ID/password-reset-link"
RESET_STATUS="$(api_full POST "/api/v2/admin/users/$TEST_USER_ID/password-reset-link" "" "$TOKEN")"
RESET_BODY="$(cat "$_TMPBODY")"
assert_http 201 "$RESET_STATUS" "POST /password-reset-link"
assert_no_error "$RESET_BODY" "password-reset-link body"
assert_field "$RESET_BODY" ".reset_url" "reset_url present"
assert_json_str "$RESET_BODY" ".token_type" "password_reset" "token_type=password_reset"
echo

# --- Step 10: Delete test user ---
echo "--- Step 10: DELETE /api/v2/admin/users/$TEST_USER_ID"
DELETE_STATUS="$(api_status DELETE "/api/v2/admin/users/$TEST_USER_ID" "" "$TOKEN")"
assert_http 204 "$DELETE_STATUS" "DELETE /admin/users/<id>"
TEST_USER_ID=""  # mark cleaned up; trap won't retry
echo

# --- Step 11: 404 on non-existent user (refactored routes via _get_user_or_404) ---
echo "--- Step 11: 404 on non-existent user (refactored routes via _get_user_or_404)"
GHOST_ID="00000000-0000-0000-0000-000000000000"

check_404() {
  local method="$1" path="$2" data="${3:-}"
  local status body err_msg
  status="$(api_full "$method" "$path" "$data" "$TOKEN")"
  body="$(cat "$_TMPBODY")"
  assert_http 404 "$status" "$method $path"
  err_msg="$(echo "$body" | jq -r '.error // empty')"
  [[ "$err_msg" == "User not found" ]] \
    || fail "$method $path: expected error='User not found', got '$err_msg'"
  ok "$method $path => {\"error\":\"User not found\"}"
}

check_404 PATCH "/api/v2/admin/users/$GHOST_ID"                    "{}"
check_404 POST  "/api/v2/admin/users/$GHOST_ID/disable"             ""
check_404 POST  "/api/v2/admin/users/$GHOST_ID/enable"              ""
check_404 POST  "/api/v2/admin/users/$GHOST_ID/verify-email"        ""
check_404 POST  "/api/v2/admin/users/$GHOST_ID/password-reset-link" ""
echo

echo "=== All checks passed ==="
