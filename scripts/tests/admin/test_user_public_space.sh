#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
USER_EMAIL="${USER_EMAIL:-}"
USER_PASSWORD="${USER_PASSWORD:-}"
USERDATA_DIR="${USERDATA_DIR:-./data/userdata}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[KO] Missing command: $1"
    exit 1
  }
}

need_cmd curl
need_cmd jq

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

api_status() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local token="${4:-}"

  if [[ -n "$data" && -n "$token" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$data" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      -d "$data"
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
  local label="$1"
  local status="$2"
  local expected="$3"
  if [[ "$status" == "$expected" ]]; then
    echo "[OK] $label"
    PASSES=$((PASSES+1))
  else
    echo "[KO] $label: expected HTTP $expected, got $status"
    FAILS=$((FAILS+1))
  fi
}

echo ""
echo "=== test_user_public_space.sh ==="
echo ""

# --- Auth ---
USER_API_KEY="${USER_API_KEY:-${TOKEN:-}}"
if [[ -n "$USER_API_KEY" ]]; then
  echo "[INFO] Using USER_API_KEY/TOKEN"
  TOKEN="$USER_API_KEY"
elif [[ -n "$USER_EMAIL" && -n "$USER_PASSWORD" ]]; then
  echo "[INFO] Logging in with USER_EMAIL/USER_PASSWORD"
  LOGIN_RESP="$(api POST "/api/v2/auth/login" "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}")"
  err="$(echo "$LOGIN_RESP" | jq -r '.error // empty')"
  if [[ -n "$err" ]]; then
    echo "[KO] Login failed: $err"
    exit 1
  fi
  TOKEN="$(echo "$LOGIN_RESP" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "[KO] Could not extract token from login response"
    exit 1
  fi
  echo "[OK] Login successful"
else
  echo "[ERROR] Set USER_API_KEY or (USER_EMAIL + USER_PASSWORD) to authenticate"
  exit 1
fi

# --- Get user ID ---
ME="$(api GET "/api/v2/me" "" "$TOKEN")"
USER_ID="$(echo "$ME" | jq -r '.id // empty')"
if [[ -z "$USER_ID" || "$USER_ID" == "null" ]]; then
  echo "[KO] Could not get user ID from /api/v2/me"
  exit 1
fi
echo "[INFO] user_id=$USER_ID"

SPACE_ROOT="${USERDATA_DIR}/${USER_ID}/local"

# --- Step 0: Create test file in nested subdirectory ---
echo ""
echo "--- Step 0: Create test file at oki/show/file.mkv"
TEST_SUBDIR="${SPACE_ROOT}/oki/show"
TEST_FILE="${TEST_SUBDIR}/file.mkv"
mkdir -p "$TEST_SUBDIR"
echo "test content" > "$TEST_FILE"
echo "[OK] Step 0: test file created at $TEST_FILE"
PASSES=$((PASSES+1))

# --- Step 1: Unauthenticated GET /api/v2/me/public-space => 401 ---
echo ""
echo "--- Step 1: Unauthenticated GET /api/v2/me/public-space => 401"
STATUS="$(api_status GET "/api/v2/me/public-space")"
check "unauthenticated GET returns 401" "$STATUS" "401"

# --- Step 2: Authenticated GET /api/v2/me/public-space ---
echo ""
echo "--- Step 2: Authenticated GET /api/v2/me/public-space"
STATUS="$(api_status GET "/api/v2/me/public-space" "" "$TOKEN")"
check "authenticated GET returns 200" "$STATUS" "200"

SPACE="$(api GET "/api/v2/me/public-space" "" "$TOKEN")"
echo "$SPACE" | jq .

SLUG="$(echo "$SPACE" | jq -r '.slug // empty')"
URL="$(echo "$SPACE" | jq -r '.url // empty')"
FILE_COUNT="$(echo "$SPACE" | jq -r '.file_count')"

if [[ -z "$SLUG" || "$SLUG" == "null" ]]; then
  echo "[KO] Step 2: slug is empty"
  FAILS=$((FAILS+1))
else
  echo "[OK] Step 2: slug present: $SLUG"
  PASSES=$((PASSES+1))
fi

if [[ -z "$URL" || "$URL" == "null" ]]; then
  echo "[KO] Step 2: url is empty"
  FAILS=$((FAILS+1))
else
  echo "[OK] Step 2: url present: $URL"
  PASSES=$((PASSES+1))
fi

NESTED_FILE="$(echo "$SPACE" | jq -r '.files[] | select(.relative_path == "oki/show/file.mkv") | .relative_path')"
if [[ "$NESTED_FILE" == "oki/show/file.mkv" ]]; then
  echo "[OK] Step 2: oki/show/file.mkv visible in API with relative_path"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 2: oki/show/file.mkv not found in API files list"
  echo "       files: $(echo "$SPACE" | jq -r '[.files[].relative_path]')"
  FAILS=$((FAILS+1))
fi

if [[ "$FILE_COUNT" -ge 1 ]]; then
  echo "[OK] Step 2: file_count >= 1 ($FILE_COUNT)"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 2: file_count=$FILE_COUNT, expected >= 1"
  FAILS=$((FAILS+1))
fi

# --- Step 3: Slug stability ---
echo ""
echo "--- Step 3: Second call returns same slug"
SLUG2="$(api GET "/api/v2/me/public-space" "" "$TOKEN" | jq -r '.slug // empty')"
if [[ "$SLUG" == "$SLUG2" ]]; then
  echo "[OK] Step 3: slug is stable"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 3: slug changed: '$SLUG' -> '$SLUG2'"
  FAILS=$((FAILS+1))
fi

# --- Step 4: Public root listing ---
echo ""
echo "--- Step 4: Public root listing at /u/<slug>/"
STATUS="$(api_status GET "/u/${SLUG}/")"
check "public root listing returns 200" "$STATUS" "200"

ROOT_HTML="$(api GET "/u/${SLUG}/")"
if echo "$ROOT_HTML" | grep -qi "<!DOCTYPE html"; then
  echo "[OK] Step 4: response is HTML"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 4: response is not HTML"
  FAILS=$((FAILS+1))
fi

# Root listing shows oki/ folder (not the file directly)
if echo "$ROOT_HTML" | grep -q ">oki<"; then
  echo "[OK] Step 4: oki folder visible in root listing"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 4: oki folder not found in root listing"
  echo "       (first 1000 chars): $(echo "$ROOT_HTML" | head -c 1000)"
  FAILS=$((FAILS+1))
fi

# --- Step 5: Browse oki/ ---
echo ""
echo "--- Step 5: Browse /u/<slug>/browse/oki"
STATUS="$(api_status GET "/u/${SLUG}/browse/oki")"
check "browse oki returns 200" "$STATUS" "200"

OKI_HTML="$(api GET "/u/${SLUG}/browse/oki")"
if echo "$OKI_HTML" | grep -qi "<!DOCTYPE html"; then
  echo "[OK] Step 5: browse oki is HTML"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 5: browse oki is not HTML"
  FAILS=$((FAILS+1))
fi

if echo "$OKI_HTML" | grep -q ">show<"; then
  echo "[OK] Step 5: show subfolder visible in oki listing"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 5: show subfolder not found in oki listing"
  FAILS=$((FAILS+1))
fi

# --- Step 6: Browse oki/show/ ---
echo ""
echo "--- Step 6: Browse /u/<slug>/browse/oki/show"
STATUS="$(api_status GET "/u/${SLUG}/browse/oki/show")"
check "browse oki/show returns 200" "$STATUS" "200"

SHOW_HTML="$(api GET "/u/${SLUG}/browse/oki/show")"
if echo "$SHOW_HTML" | grep -q ">file.mkv<"; then
  echo "[OK] Step 6: file.mkv visible in oki/show listing"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 6: file.mkv not found in oki/show listing"
  FAILS=$((FAILS+1))
fi

# --- Step 7: Download nested file ---
echo ""
echo "--- Step 7: Download /u/<slug>/files/oki/show/file.mkv => 200"
STATUS="$(api_status GET "/u/${SLUG}/files/oki/show/file.mkv")"
check "nested file download returns 200" "$STATUS" "200"

# --- Step 8: Invalid slug => 404 ---
echo ""
echo "--- Step 8: Invalid slug returns 404"
STATUS="$(api_status GET "/u/invalid-slug-does-not-exist/")"
check "invalid slug returns 404" "$STATUS" "404"

# --- Step 9: Non-existent browse dir => 404 ---
echo ""
echo "--- Step 9: Non-existent browse dir returns 404"
STATUS="$(api_status GET "/u/${SLUG}/browse/does-not-exist")"
check "non-existent browse dir returns 404" "$STATUS" "404"

# --- Step 10: Non-existent file => 404 ---
echo ""
echo "--- Step 10: Non-existent file returns 404"
STATUS="$(api_status GET "/u/${SLUG}/files/does-not-exist.txt")"
check "non-existent file returns 404" "$STATUS" "404"

# --- Step 11: Path traversal blocked ---
echo ""
echo "--- Step 11: Path traversal blocked"

# Encoded traversal in files route
TRAV1="$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/u/${SLUG}/files/..%2F..%2Fetc%2Fpasswd")"
if [[ "$TRAV1" == "400" || "$TRAV1" == "404" ]]; then
  echo "[OK] Step 11: encoded traversal in files blocked (HTTP $TRAV1)"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 11: encoded traversal in files not blocked (HTTP $TRAV1)"
  FAILS=$((FAILS+1))
fi

# Double-dot in path component (files)
TRAV2="$(api_status GET "/u/${SLUG}/files/oki/../../../etc/passwd")"
if [[ "$TRAV2" == "400" || "$TRAV2" == "404" ]]; then
  echo "[OK] Step 11: .. in files path blocked (HTTP $TRAV2)"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 11: .. in files path not blocked (HTTP $TRAV2)"
  FAILS=$((FAILS+1))
fi

# Hidden directory in browse route (starts with dot)
TRAV3="$(api_status GET "/u/${SLUG}/browse/.hidden")"
if [[ "$TRAV3" == "400" || "$TRAV3" == "404" ]]; then
  echo "[OK] Step 11: hidden dir in browse blocked (HTTP $TRAV3)"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 11: hidden dir in browse not blocked (HTTP $TRAV3)"
  FAILS=$((FAILS+1))
fi

# --- Step 12: Unauthenticated cleanup => 401 ---
echo ""
echo "--- Step 12: Unauthenticated cleanup => 401"
STATUS="$(api_status POST "/api/v2/me/public-space/cleanup")"
check "unauthenticated cleanup returns 401" "$STATUS" "401"

# --- Step 13: Authenticated cleanup ---
echo ""
echo "--- Step 13: Authenticated cleanup"
CLEANUP_BODY="$(mktemp)"
CLEANUP_STATUS="$(curl -sS -o "$CLEANUP_BODY" -w "%{http_code}" -X POST "$BASE_URL/api/v2/me/public-space/cleanup" \
  -H "X-Api-Key: $TOKEN")"
check "cleanup returns 200" "$CLEANUP_STATUS" "200"
CLEANUP="$(cat "$CLEANUP_BODY")"
rm -f "$CLEANUP_BODY"
echo "$CLEANUP" | jq .

if [[ "$(echo "$CLEANUP" | jq -r '.ok')" == "true" ]]; then
  echo "[OK] Step 13: ok=true"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 13: ok not true"
  FAILS=$((FAILS+1))
fi

DELETED="$(echo "$CLEANUP" | jq -r '.deleted_count')"
if [[ "$DELETED" -ge 1 ]]; then
  echo "[OK] Step 13: deleted_count=$DELETED (>= 1)"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 13: deleted_count=$DELETED, expected >= 1"
  FAILS=$((FAILS+1))
fi

if echo "$CLEANUP" | jq -r '.deleted_files[]' | grep -q "oki/show/file.mkv"; then
  echo "[OK] Step 13: oki/show/file.mkv in deleted_files"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 13: oki/show/file.mkv not in deleted_files"
  echo "       deleted_files: $(echo "$CLEANUP" | jq '.deleted_files')"
  FAILS=$((FAILS+1))
fi

# --- Step 14: After cleanup, disk is clean ---
echo ""
echo "--- Step 14: Subdirectory removed after cleanup"
if [[ ! -d "${SPACE_ROOT}/oki" ]]; then
  echo "[OK] Step 14: oki/ directory removed"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 14: oki/ directory still exists"
  FAILS=$((FAILS+1))
fi

if [[ ! -f "${TEST_FILE}" ]]; then
  echo "[OK] Step 14: file.mkv removed"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 14: file.mkv still exists"
  FAILS=$((FAILS+1))
fi

if [[ -d "${SPACE_ROOT}" ]]; then
  echo "[OK] Step 14: local/ directory preserved"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 14: local/ directory was removed (should be preserved)"
  FAILS=$((FAILS+1))
fi

# --- Step 15: file_count is 0 after cleanup ---
echo ""
echo "--- Step 15: file_count is 0 after cleanup"
FC="$(api GET "/api/v2/me/public-space" "" "$TOKEN" | jq -r '.file_count')"
if [[ "$FC" == "0" ]]; then
  echo "[OK] Step 15: file_count=0"
  PASSES=$((PASSES+1))
else
  echo "[KO] Step 15: file_count=$FC, expected 0"
  FAILS=$((FAILS+1))
fi

# --- Summary ---
echo ""
echo "=== Results: ${PASSES} passed, ${FAILS} failed ==="
echo ""

if [[ $FAILS -gt 0 ]]; then
  exit 1
fi
