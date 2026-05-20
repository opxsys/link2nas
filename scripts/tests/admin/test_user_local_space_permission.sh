#!/usr/bin/env bash
set -euo pipefail

# Test script for can_use_local_space permission enforcement.
#
# Requirements:
#   ADMIN_API_KEY  — super_admin key to create/update users
#   BASE_URL       — server base URL (default: http://127.0.0.1:5000)
#   USERDATA_DIR   — path to userdata directory (default: ./data/userdata)
#   TEST_USER_EMAIL / TEST_USER_PASSWORD — credentials for test user (created by script or pre-existing)
#                                           Leave blank to let the script create a fresh user.

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_API_KEY="${ADMIN_API_KEY:-}"
USERDATA_DIR="${USERDATA_DIR:-./data/userdata}"
TEST_USER_EMAIL="${TEST_USER_EMAIL:-}"
TEST_USER_PASSWORD="${TEST_USER_PASSWORD:-TestPass1234!}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}
need_cmd curl
need_cmd jq

api() {
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  if [[ -n "$data" && -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" -H "X-Api-Key: $token" -H "Content-Type: application/json" -d "$data"
  elif [[ -n "$data" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" -H "Content-Type: application/json" -d "$data"
  elif [[ -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" -H "X-Api-Key: $token"
  else
    curl -sS -X "$method" "$BASE_URL$path"
  fi
}

api_status() {
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  if [[ -n "$data" && -n "$token" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" -H "Content-Type: application/json" -d "$data"
  elif [[ -n "$data" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" -d "$data"
  elif [[ -n "$token" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token"
  else
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path"
  fi
}

PASSES=0
FAILS=0

check() {
  local label="$1" status="$2" expected="$3"
  if [[ "$status" == "$expected" ]]; then
    echo "[OK] $label"
    PASSES=$((PASSES+1))
  else
    echo "[KO] $label: expected HTTP $expected, got $status"
    FAILS=$((FAILS+1))
  fi
}

check_val() {
  local label="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "[OK] $label"
    PASSES=$((PASSES+1))
  else
    echo "[KO] $label: expected '$expected', got '$actual'"
    FAILS=$((FAILS+1))
  fi
}

echo ""
echo "=== test_user_local_space_permission.sh ==="
echo ""

if [[ -z "$ADMIN_API_KEY" ]]; then
  ADMIN_EMAIL="${ADMIN_EMAIL:-admin@link2nas.local}"
  ADMIN_PASSWORD="${ADMIN_PASSWORD:-${ADMIN_PASS:-change-me-strong-password}}"
  echo "[INFO] ADMIN_API_KEY not set, logging in as $ADMIN_EMAIL"
  _LOGIN="$(api POST "/api/v2/auth/login" "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
  ADMIN_API_KEY="$(echo "$_LOGIN" | jq -r '.token // empty')"
  if [[ -z "$ADMIN_API_KEY" || "$ADMIN_API_KEY" == "null" ]]; then
    echo "[ERROR] Admin login failed"
    echo "        response: $_LOGIN"
    exit 1
  fi
  echo "[OK] Admin login successful"
fi

# --- Step 0: Create test user with can_use_local_space=false ---
echo ""
echo "--- Step 0: Create test user with can_use_local_space=false"

if [[ -z "$TEST_USER_EMAIL" ]]; then
  TEST_USER_EMAIL="test-local-space-$(date +%s)@example.com"
fi

CREATE_BODY="$(api POST "/api/v2/admin/users" \
  "{\"email\":\"$TEST_USER_EMAIL\",\"password\":\"$TEST_USER_PASSWORD\",\"creation_mode\":\"password\",\"can_use_local_space\":false,\"email_verified\":true}" \
  "$ADMIN_API_KEY")"

USER_ID="$(echo "$CREATE_BODY" | jq -r '.id // empty')"
if [[ -z "$USER_ID" || "$USER_ID" == "null" ]]; then
  echo "[KO] Could not create test user"
  echo "       response: $CREATE_BODY"
  exit 1
fi
echo "[OK] Test user created: $USER_ID ($TEST_USER_EMAIL)"
PASSES=$((PASSES+1))

# --- Login as test user ---
LOGIN_RESP="$(api POST "/api/v2/auth/login" \
  "{\"email\":\"$TEST_USER_EMAIL\",\"password\":\"$TEST_USER_PASSWORD\"}")"
TOKEN="$(echo "$LOGIN_RESP" | jq -r '.token // empty')"
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "[KO] Login failed"
  echo "       response: $LOGIN_RESP"
  exit 1
fi
echo "[OK] Login successful"
PASSES=$((PASSES+1))

# --- Step 1: /me returns can_use_local_space=false ---
echo ""
echo "--- Step 1: GET /api/v2/me returns can_use_local_space=false"
ME="$(api GET "/api/v2/me" "" "$TOKEN")"
CAN="$(echo "$ME" | jq -r '.can_use_local_space')"
check_val "/me.can_use_local_space is false" "$CAN" "false"

# --- Step 2: GET /api/v2/me/public-space => 403 ---
echo ""
echo "--- Step 2: GET /api/v2/me/public-space => 403"
STATUS="$(api_status GET "/api/v2/me/public-space" "" "$TOKEN")"
check "GET public-space returns 403" "$STATUS" "403"

# --- Step 3: POST /api/v2/me/public-space/cleanup => 403 ---
echo ""
echo "--- Step 3: POST /api/v2/me/public-space/cleanup => 403"
STATUS="$(api_status POST "/api/v2/me/public-space/cleanup" "" "$TOKEN")"
check "POST cleanup returns 403" "$STATUS" "403"

# --- Step 4: Force a public_slug via admin and test /u/<slug>/ => 404 ---
echo ""
echo "--- Step 4: Public URL /u/<slug>/ => 404 when right is false"

# Grant right temporarily to get a slug, then remove it
PATCH_GRANT="$(api PATCH "/api/v2/admin/users/$USER_ID" \
  '{"can_use_local_space":true}' "$ADMIN_API_KEY")"

# Fetch slug
SPACE="$(api GET "/api/v2/me/public-space" "" "$TOKEN")"
SLUG="$(echo "$SPACE" | jq -r '.slug // empty')"
if [[ -z "$SLUG" || "$SLUG" == "null" ]]; then
  echo "[KO] Step 4: could not get slug after granting right"
  FAILS=$((FAILS+1))
else
  echo "[OK] Step 4: got slug=$SLUG"
  PASSES=$((PASSES+1))

  # Revoke right
  api PATCH "/api/v2/admin/users/$USER_ID" '{"can_use_local_space":false}' "$ADMIN_API_KEY" > /dev/null

  # Now the public URL should 404
  STATUS="$(api_status GET "/u/${SLUG}/")"
  check "GET /u/<slug>/ returns 404 when right revoked" "$STATUS" "404"
fi

# --- Step 5: Destination local creation => 403 ---
echo ""
echo "--- Step 5: Create local destination => 403"
STATUS="$(api_status POST "/api/v2/destinations" \
  '{"destination_type":"local","name":"test-local","config_json":"{\"base_path\":\"downloads\"}"}' \
  "$TOKEN")"
check "Create local destination returns 403" "$STATUS" "403"

# --- Step 6: Grant can_use_local_space=true via admin ---
echo ""
echo "--- Step 6: Grant can_use_local_space=true via admin"
PATCH_RESP="$(api PATCH "/api/v2/admin/users/$USER_ID" \
  '{"can_use_local_space":true}' "$ADMIN_API_KEY")"
CAN2="$(echo "$PATCH_RESP" | jq -r '.can_use_local_space')"
check_val "admin PATCH sets can_use_local_space=true" "$CAN2" "true"

# --- Step 7: /me now returns can_use_local_space=true ---
echo ""
echo "--- Step 7: GET /api/v2/me returns can_use_local_space=true"
ME2="$(api GET "/api/v2/me" "" "$TOKEN")"
CAN3="$(echo "$ME2" | jq -r '.can_use_local_space')"
check_val "/me.can_use_local_space is true" "$CAN3" "true"

# --- Step 8: GET /api/v2/me/public-space => 200 ---
echo ""
echo "--- Step 8: GET /api/v2/me/public-space => 200"
STATUS="$(api_status GET "/api/v2/me/public-space" "" "$TOKEN")"
check "GET public-space returns 200" "$STATUS" "200"

SPACE2="$(api GET "/api/v2/me/public-space" "" "$TOKEN")"
SLUG2="$(echo "$SPACE2" | jq -r '.slug // empty')"
if [[ -z "$SLUG2" || "$SLUG2" == "null" ]]; then
  echo "[KO] Step 8: no slug returned"
  FAILS=$((FAILS+1))
else
  echo "[OK] Step 8: slug=$SLUG2"
  PASSES=$((PASSES+1))
fi

# --- Step 9: Create test file and verify /u/<slug>/ => 200 ---
echo ""
echo "--- Step 9: Create test file, verify public listing"
SPACE_ROOT="${USERDATA_DIR}/${USER_ID}/local"
TEST_DIR="${SPACE_ROOT}/test"
TEST_FILE="${TEST_DIR}/permission-test.txt"
mkdir -p "$TEST_DIR"
echo "test" > "$TEST_FILE"
echo "[OK] Step 9: created $TEST_FILE"
PASSES=$((PASSES+1))

STATUS="$(api_status GET "/u/${SLUG2}/")"
check "GET /u/<slug>/ returns 200 when right granted" "$STATUS" "200"

# --- Step 10: POST cleanup => 200 ---
echo ""
echo "--- Step 10: POST cleanup => 200"
CLEANUP_TMP="$(mktemp)"
CLEANUP_STATUS="$(curl -sS -o "$CLEANUP_TMP" -w "%{http_code}" -X POST \
  "$BASE_URL/api/v2/me/public-space/cleanup" -H "X-Api-Key: $TOKEN")"
check "POST cleanup returns 200" "$CLEANUP_STATUS" "200"
CLEANUP="$(cat "$CLEANUP_TMP")"
rm -f "$CLEANUP_TMP"
check_val "cleanup ok=true" "$(echo "$CLEANUP" | jq -r '.ok')" "true"

# --- Step 11: Revoke can_use_local_space ---
echo ""
echo "--- Step 11: Revoke can_use_local_space=false"
api PATCH "/api/v2/admin/users/$USER_ID" '{"can_use_local_space":false}' "$ADMIN_API_KEY" > /dev/null
STATUS="$(api_status GET "/api/v2/me/public-space" "" "$TOKEN")"
check "GET public-space returns 403 after revocation" "$STATUS" "403"

STATUS="$(api_status GET "/u/${SLUG2}/")"
check "GET /u/<slug>/ returns 404 after revocation" "$STATUS" "404"

# --- Step 12: Files NOT deleted automatically when right revoked ---
echo ""
echo "--- Step 12: Files not deleted automatically on revocation"
# Re-create test file (was cleaned in step 10)
mkdir -p "$TEST_DIR"
echo "test" > "$TEST_FILE"
# Revoke (already revoked but do it again for clarity)
api PATCH "/api/v2/admin/users/$USER_ID" '{"can_use_local_space":false}' "$ADMIN_API_KEY" > /dev/null

if [[ -f "$TEST_FILE" ]]; then
  echo "[OK] Step 12: file preserved after revocation (no auto-delete)"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 12: file was deleted automatically — should not happen"
  FAILS=$((FAILS+1))
fi

# --- Cleanup: delete test user ---
echo ""
echo "--- Cleanup: delete test user and files"
rm -rf "${USERDATA_DIR}/${USER_ID}" 2>/dev/null || true
api DELETE "/api/v2/admin/users/$USER_ID" "" "$ADMIN_API_KEY" > /dev/null && echo "[INFO] Test user deleted"

# --- Summary ---
echo ""
echo "=== Results: ${PASSES} passed, ${FAILS} failed ==="
echo ""

if [[ $FAILS -gt 0 ]]; then
  exit 1
fi
