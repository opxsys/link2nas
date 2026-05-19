#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
DB_PATH="${DB_PATH-data/link2nas_v2.sqlite3}"

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%Y%m%d%H%M%S)-$$"
KEY_NAME="Prowlarr test key $RUN_ID"
NO_SCOPE_KEY_NAME="No qbit scope test key $RUN_ID"
SCOPE="qbittorrent:write"

echo "[TEST] qBittorrent compatibility API"
echo "[TEST] BASE_URL=$BASE_URL"
echo "[TEST] DB_PATH=$DB_PATH"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[OK] $*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

require_cmd curl
require_cmd jq

echo "[TEST] setup status"
SETUP_STATUS="$(curl -s "$BASE_URL/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq . >/dev/null

SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo "[TEST] creating first admin"
  curl -s -X POST "$BASE_URL/api/v2/setup/first-admin" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\":\"$ADMIN_EMAIL\",
      \"display_name\":\"QBit Test Admin\",
      \"password\":\"$ADMIN_PASSWORD\"
    }" | jq . >/dev/null
else
  echo "[TEST] setup already done"
fi

echo "[TEST] login"
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN_RESPONSE="$(curl -s -X POST "$BASE_URL/api/v2/auth/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\":\"$ADMIN_EMAIL\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  if ! echo "$LOGIN_RESPONSE" | jq . >/dev/null 2>&1; then
    fail "Login response is not JSON: $LOGIN_RESPONSE"
  fi
  TOKEN="$(echo "$LOGIN_RESPONSE" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    fail "Unable to login. If this is an existing DB, set ADMIN_EMAIL and ADMIN_PASSWORD to a valid user."
  fi
  pass "web login OK"
fi

echo "[TEST] create user API key with qbittorrent:write"
API_KEY_RESPONSE="$(curl -s -X POST "$BASE_URL/api/v2/me/api-keys" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "{
    \"name\":\"$KEY_NAME\",
    \"scopes\":[\"$SCOPE\"]
  }")"

QBIT_KEY="$(echo "$API_KEY_RESPONSE" | jq -r '.key // empty')"

if [[ -z "$QBIT_KEY" || "$QBIT_KEY" == "null" ]]; then
  fail "Unable to create qBittorrent API key: $API_KEY_RESPONSE"
fi

pass "qBittorrent scoped key created"

echo "[TEST] create API key without qbittorrent scope"
NO_SCOPE_RESPONSE="$(curl -s -X POST "$BASE_URL/api/v2/me/api-keys" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "{
    \"name\":\"$NO_SCOPE_KEY_NAME\",
    \"scopes\":[\"jobs:read\"]
  }")"

NO_SCOPE_KEY="$(echo "$NO_SCOPE_RESPONSE" | jq -r '.key // empty')"

if [[ -z "$NO_SCOPE_KEY" || "$NO_SCOPE_KEY" == "null" ]]; then
  fail "Unable to create no-scope API key: $NO_SCOPE_RESPONSE"
fi

pass "non-qBittorrent key created"

echo "[TEST] qBittorrent login OK"
LOGIN_STATUS="$(curl -s -o /tmp/l2n_qbit_login.out -w "%{http_code}" \
  -c /tmp/l2n_qbit.cookies \
  -X POST "$BASE_URL/qbittorrent/api/v2/auth/login" \
  -d "username=prowlarr" \
  -d "password=$QBIT_KEY")"

LOGIN_BODY="$(cat /tmp/l2n_qbit_login.out)"

[[ "$LOGIN_STATUS" == "200" ]] || fail "qBittorrent login returned $LOGIN_STATUS: $LOGIN_BODY"
[[ "$LOGIN_BODY" == "Ok." ]] || fail "qBittorrent login body unexpected: $LOGIN_BODY"

pass "qBittorrent login OK"

echo "[TEST] qBittorrent login rejects missing scope"
NO_SCOPE_STATUS="$(curl -s -o /tmp/l2n_qbit_noscope.out -w "%{http_code}" \
  -X POST "$BASE_URL/qbittorrent/api/v2/auth/login" \
  -d "username=prowlarr" \
  -d "password=$NO_SCOPE_KEY")"

[[ "$NO_SCOPE_STATUS" == "403" ]] || fail "No-scope key should return 403, got $NO_SCOPE_STATUS"

pass "scope check OK"

echo "[TEST] app/version"
VERSION="$(curl -s -H "X-Api-Key: $QBIT_KEY" "$BASE_URL/qbittorrent/api/v2/app/version")"
[[ "$VERSION" == "4.6.0" ]] || fail "Unexpected version: $VERSION"
pass "app/version OK"

echo "[TEST] app/webapiVersion"
WEBAPI_VERSION="$(curl -s -H "X-Api-Key: $QBIT_KEY" "$BASE_URL/qbittorrent/api/v2/app/webapiVersion")"
[[ "$WEBAPI_VERSION" == "2.11.0" ]] || fail "Unexpected webapiVersion: $WEBAPI_VERSION"
pass "app/webapiVersion OK"

echo "[TEST] app/preferences"
PREFERENCES="$(curl -s -H "X-Api-Key: $QBIT_KEY" "$BASE_URL/qbittorrent/api/v2/app/preferences")"
echo "$PREFERENCES" | jq . >/dev/null
SAVE_PATH="$(echo "$PREFERENCES" | jq -r '.save_path')"
[[ "$SAVE_PATH" == "/link2nas" ]] || fail "Unexpected save_path: $SAVE_PATH"
pass "app/preferences OK"

echo "[TEST] torrents/info"
INFO="$(curl -s -H "X-Api-Key: $QBIT_KEY" "$BASE_URL/qbittorrent/api/v2/torrents/info")"
echo "$INFO" | jq . >/dev/null
INFO_LEN="$(echo "$INFO" | jq 'length')"
[[ "$INFO_LEN" == "0" ]] || fail "torrents/info should return empty array"
pass "torrents/info OK"

echo "[TEST] torrents/categories"
CATEGORIES="$(curl -s -H "X-Api-Key: $QBIT_KEY" "$BASE_URL/qbittorrent/api/v2/torrents/categories")"
echo "$CATEGORIES" | jq . >/dev/null
CATEGORY_NAME="$(echo "$CATEGORIES" | jq -r '.prowlarr.name')"
[[ "$CATEGORY_NAME" == "prowlarr" ]] || fail "Missing prowlarr category"
pass "torrents/categories OK"

echo "[TEST] torrents/add rejects empty payload"
ADD_EMPTY_STATUS="$(curl -s -o /tmp/l2n_qbit_add_empty.out -w "%{http_code}" \
  -H "X-Api-Key: $QBIT_KEY" \
  -X POST "$BASE_URL/qbittorrent/api/v2/torrents/add")"

[[ "$ADD_EMPTY_STATUS" == "400" ]] || fail "Empty torrents/add should return 400, got $ADD_EMPTY_STATUS"
pass "torrents/add empty payload validation OK"

echo "[TEST] audit table presence"

if [[ -f "$DB_PATH" ]]; then
  command -v sqlite3 >/dev/null 2>&1 || fail "sqlite3 missing"

  TABLE_EXISTS="$(sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name='external_client_submissions';")"

  [[ "$TABLE_EXISTS" == "external_client_submissions" ]] || fail "external_client_submissions table missing in $DB_PATH"

  pass "SQLite audit table exists"
else
  echo "[WARN] DB_PATH not found, skipping SQLite table check: $DB_PATH"
fi

echo "[TEST] done"
