#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%Y%m%d%H%M%S)-$$"

echo "=== Link2NAS V3 announcements backend test ==="
echo "BASE_URL=$BASE_URL"
echo "RUN_ID=$RUN_ID"
echo

# ---- helpers ----------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
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

_BODY_FILE="/tmp/l2n_ann_test_$$.json"

api_with_status() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local token="${4:-}"

  if [[ -n "$data" && -n "$token" ]]; then
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$data" ]]; then
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$token" ]]; then
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token"
  else
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path"
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

assert_http() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label: expected HTTP $expected, got HTTP $actual"
    jq . "$_BODY_FILE" 2>/dev/null || cat "$_BODY_FILE"
    echo
    exit 1
  fi
  echo "[OK] $label (HTTP $actual)"
}

assert_body_contains() {
  local label="$1"
  local jq_expr="$2"
  local value
  value="$(jq -r "$jq_expr // empty" "$_BODY_FILE")"
  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "[KO] $label: $jq_expr not found or null in response"
    jq . "$_BODY_FILE" 2>/dev/null || cat "$_BODY_FILE"
    exit 1
  fi
  echo "[OK] $label ($jq_expr present)"
}

assert_json_field() {
  local json="$1"
  local jq_expr="$2"
  local expected="$3"
  local label="$4"
  local actual
  actual="$(echo "$json" | jq -r "$jq_expr")"
  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label: expected '$expected', got '$actual'"
    exit 1
  fi
  echo "[OK] $label"
}

assert_json_bool() {
  local json="$1"
  local jq_expr="$2"
  local expected="$3"
  local label="$4"
  local actual
  actual="$(echo "$json" | jq "$jq_expr")"
  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label: expected $expected, got $actual"
    exit 1
  fi
  echo "[OK] $label"
}

assert_non_empty() {
  local value="$1"
  local label="$2"
  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "[KO] $label: value is empty or null"
    exit 1
  fi
  echo "[OK] $label"
}

assert_array_contains_id() {
  local json="$1"
  local id="$2"
  local label="$3"
  local found
  found="$(echo "$json" | jq -r --arg id "$id" 'map(select(.id == $id)) | length')"
  if [[ "$found" -lt 1 ]]; then
    echo "[KO] $label: id $id not found in array"
    exit 1
  fi
  echo "[OK] $label (id $id found)"
}

# ---- state & cleanup --------------------------------------------------------

TOKEN="${TOKEN:-}"
ME_ID=""
ANN_ID=""
ANN_ID2=""

cleanup() {
  echo
  echo "--- Cleanup ---"
  if [[ -n "$ANN_ID" && -n "$TOKEN" ]]; then
    api DELETE "/api/v2/admin/announcements/$ANN_ID" "" "$TOKEN" >/dev/null 2>&1 || true
    echo "[INFO] Announcement $ANN_ID soft-deleted."
  fi
  if [[ -n "$ANN_ID2" && -n "$TOKEN" ]]; then
    api DELETE "/api/v2/admin/announcements/$ANN_ID2" "" "$TOKEN" >/dev/null 2>&1 || true
    echo "[INFO] Announcement $ANN_ID2 soft-deleted."
  fi
  rm -f "$_BODY_FILE"
}
trap cleanup EXIT

need_cmd curl
need_cmd jq

# ---- 1. Setup / Auth --------------------------------------------------------

echo "=== 1) Setup / Auth ==="
echo

SETUP_STATUS="$(api GET "/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo
  echo "--- Creating first admin ---"
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
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN="$(api POST "/api/v2/auth/login" "{
    \"email\":\"$ADMIN_EMAIL\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  echo "$LOGIN" | jq
  assert_no_error "$LOGIN" "admin login"
  TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
  assert_non_empty "$TOKEN" "admin token received"
fi

echo
ME="$(api GET "/api/v2/me" "" "$TOKEN")"
echo "$ME" | jq
assert_no_error "$ME" "GET /me"

ME_ID="$(echo "$ME" | jq -r '.id // empty')"
assert_non_empty "$ME_ID" "me.id present"

RAE="$(echo "$ME" | jq '.receive_application_emails')"
if [[ "$RAE" != "true" && "$RAE" != "false" ]]; then
  echo "[KO] receive_application_emails not present or not bool in /me (got: $RAE)"
  exit 1
fi
echo "[OK] receive_application_emails present in /me (value: $RAE)"

echo
echo "--- PATCH receive_application_emails → true ---"
PATCH_TRUE="$(api PATCH "/api/v2/me" '{"receive_application_emails": true}' "$TOKEN")"
echo "$PATCH_TRUE" | jq
assert_no_error "$PATCH_TRUE" "PATCH /me receive_application_emails=true"
assert_json_bool "$PATCH_TRUE" '.receive_application_emails' "true" "receive_application_emails is true"

echo
echo "--- PATCH receive_application_emails → false ---"
PATCH_FALSE="$(api PATCH "/api/v2/me" '{"receive_application_emails": false}' "$TOKEN")"
echo "$PATCH_FALSE" | jq
assert_no_error "$PATCH_FALSE" "PATCH /me receive_application_emails=false"
assert_json_bool "$PATCH_FALSE" '.receive_application_emails' "false" "receive_application_emails is false"

# ---- 2. Create valid announcement -------------------------------------------

echo
echo "=== 2) Create valid announcement ==="
echo

STATUS="$(api_with_status POST "/api/v2/admin/announcements" "{
  \"title\": \"Maintenance test $RUN_ID\",
  \"body\": \"Backend announcement test body\",
  \"type\": \"maintenance\",
  \"severity\": \"warning\",
  \"is_active\": true,
  \"show_as_banner\": true,
  \"require_acknowledgement\": true,
  \"track_open\": true,
  \"send_email\": false
}" "$TOKEN")"

ANN_JSON="$(cat "$_BODY_FILE")"
echo "$ANN_JSON" | jq
assert_http "$STATUS" "201" "POST /admin/announcements → 201"
assert_no_error "$ANN_JSON" "create announcement"

ANN_ID="$(echo "$ANN_JSON" | jq -r '.id // empty')"
assert_non_empty "$ANN_ID" "announcement id present"
assert_json_field "$ANN_JSON" '.title' "Maintenance test $RUN_ID" "title correct"
assert_json_field "$ANN_JSON" '.type' "maintenance" "type=maintenance"
assert_json_field "$ANN_JSON" '.severity' "warning" "severity=warning"
assert_json_bool "$ANN_JSON" '.send_email' "false" "send_email=false"
assert_json_bool "$ANN_JSON" '.is_active' "true" "is_active=true"
assert_json_bool "$ANN_JSON" '.require_acknowledgement' "true" "require_acknowledgement=true"
assert_json_bool "$ANN_JSON" '.track_open' "true" "track_open=true"
assert_json_bool "$ANN_JSON" '.show_as_banner' "true" "show_as_banner=true"

# ---- 3. Admin list ----------------------------------------------------------

echo
echo "=== 3) Admin list ==="
echo

LIST_ADMIN="$(api GET "/api/v2/admin/announcements" "" "$TOKEN")"
echo "$LIST_ADMIN" | jq
assert_array_contains_id "$LIST_ADMIN" "$ANN_ID" "announcement present in admin list"

# ---- 4. Admin GET by id -----------------------------------------------------

echo
echo "=== 4) Admin GET by id ==="
echo

STATUS_GET="$(api_with_status GET "/api/v2/admin/announcements/$ANN_ID" "" "$TOKEN")"
GET_ANN="$(cat "$_BODY_FILE")"
echo "$GET_ANN" | jq
assert_http "$STATUS_GET" "200" "GET /admin/announcements/$ANN_ID → 200"
assert_no_error "$GET_ANN" "GET announcement no error"
assert_json_field "$GET_ANN" '.id' "$ANN_ID" "id matches"

# ---- 5. Active user list ----------------------------------------------------

echo
echo "=== 5) Active announcements (user view) ==="
echo

ACTIVE="$(api GET "/api/v2/announcements/active" "" "$TOKEN")"
echo "$ACTIVE" | jq
assert_array_contains_id "$ACTIVE" "$ANN_ID" "announcement present in active list"

USER_STATUS="$(echo "$ACTIVE" | jq -r --arg id "$ANN_ID" \
  'map(select(.id == $id)) | .[0].user_status | tostring')"
assert_non_empty "$USER_STATUS" "user_status field present"

OPENED_AT="$(echo "$ACTIVE" | jq -r --arg id "$ANN_ID" \
  'map(select(.id == $id)) | .[0].user_status.opened_at')"
READ_AT="$(echo "$ACTIVE" | jq -r --arg id "$ANN_ID" \
  'map(select(.id == $id)) | .[0].user_status.read_at')"
ACK_AT="$(echo "$ACTIVE" | jq -r --arg id "$ANN_ID" \
  'map(select(.id == $id)) | .[0].user_status.acknowledged_at')"

[[ "$OPENED_AT" == "null" ]] \
  && echo "[OK] opened_at=null initially" \
  || { echo "[KO] expected opened_at=null, got '$OPENED_AT'"; exit 1; }
[[ "$READ_AT" == "null" ]] \
  && echo "[OK] read_at=null initially" \
  || { echo "[KO] expected read_at=null, got '$READ_AT'"; exit 1; }
[[ "$ACK_AT" == "null" ]] \
  && echo "[OK] acknowledged_at=null initially" \
  || { echo "[KO] expected acknowledged_at=null, got '$ACK_AT'"; exit 1; }

# ---- 6. Tracking open / read / acknowledge ----------------------------------

echo
echo "=== 6) Tracking: open / read / acknowledge ==="
echo

OPEN_RESP="$(api POST "/api/v2/announcements/$ANN_ID/open" "" "$TOKEN")"
echo "$OPEN_RESP" | jq
assert_json_bool "$OPEN_RESP" '.ok' "true" "POST /open → ok=true"

READ_RESP="$(api POST "/api/v2/announcements/$ANN_ID/read" "" "$TOKEN")"
echo "$READ_RESP" | jq
assert_json_bool "$READ_RESP" '.ok' "true" "POST /read → ok=true"

ACK_RESP="$(api POST "/api/v2/announcements/$ANN_ID/acknowledge" "" "$TOKEN")"
echo "$ACK_RESP" | jq
assert_json_bool "$ACK_RESP" '.ok' "true" "POST /acknowledge → ok=true"

echo
echo "--- GET tracking ---"
TRACKING="$(api GET "/api/v2/admin/announcements/$ANN_ID/tracking" "" "$TOKEN")"
echo "$TRACKING" | jq
assert_no_error "$TRACKING" "GET tracking"

OPENED_COUNT="$(echo "$TRACKING" | jq '.stats.opened')"
READ_COUNT="$(echo "$TRACKING" | jq '.stats.read')"
ACK_COUNT="$(echo "$TRACKING" | jq '.stats.acknowledged')"

[[ "$OPENED_COUNT" -ge 1 ]] \
  && echo "[OK] stats.opened >= 1" \
  || { echo "[KO] stats.opened expected >= 1, got $OPENED_COUNT"; exit 1; }
[[ "$READ_COUNT" -ge 1 ]] \
  && echo "[OK] stats.read >= 1" \
  || { echo "[KO] stats.read expected >= 1, got $READ_COUNT"; exit 1; }
[[ "$ACK_COUNT" -ge 1 ]] \
  && echo "[OK] stats.acknowledged >= 1" \
  || { echo "[KO] stats.acknowledged expected >= 1, got $ACK_COUNT"; exit 1; }

READS_FOR_USER="$(echo "$TRACKING" | jq -r --arg uid "$ME_ID" \
  '[.reads[] | select(.user_id == $uid)] | length')"
[[ "$READS_FOR_USER" -ge 1 ]] \
  && echo "[OK] reads contains entry for current user ($ME_ID)" \
  || { echo "[KO] no read entry for user $ME_ID in tracking"; exit 1; }

# ---- 7. Idempotence ---------------------------------------------------------

echo
echo "=== 7) Idempotence ==="
echo

assert_json_bool \
  "$(api POST "/api/v2/announcements/$ANN_ID/open" "" "$TOKEN")" \
  '.ok' "true" "POST /open idempotent"

assert_json_bool \
  "$(api POST "/api/v2/announcements/$ANN_ID/read" "" "$TOKEN")" \
  '.ok' "true" "POST /read idempotent"

assert_json_bool \
  "$(api POST "/api/v2/announcements/$ANN_ID/acknowledge" "" "$TOKEN")" \
  '.ok' "true" "POST /acknowledge idempotent"

TRACKING_IDEM="$(api GET "/api/v2/admin/announcements/$ANN_ID/tracking" "" "$TOKEN")"
READS_COUNT="$(echo "$TRACKING_IDEM" | jq -r --arg uid "$ME_ID" \
  '[.reads[] | select(.user_id == $uid)] | length')"
[[ "$READS_COUNT" -eq 1 ]] \
  && echo "[OK] no duplicate read entry for same user" \
  || { echo "[KO] expected 1 read entry for user, got $READS_COUNT"; exit 1; }

# ---- 8. PATCH announcement --------------------------------------------------

echo
echo "=== 8) PATCH announcement ==="
echo

STATUS_PATCH="$(api_with_status PATCH "/api/v2/admin/announcements/$ANN_ID" \
  '{"severity": "critical", "show_as_banner": false}' "$TOKEN")"
PATCH_ANN="$(cat "$_BODY_FILE")"
echo "$PATCH_ANN" | jq
assert_http "$STATUS_PATCH" "200" "PATCH /admin/announcements/$ANN_ID → 200"
assert_no_error "$PATCH_ANN" "PATCH announcement"
assert_json_field "$PATCH_ANN" '.severity' "critical" "severity updated to critical"
assert_json_bool "$PATCH_ANN" '.show_as_banner' "false" "show_as_banner updated to false"

# ---- 9. Negative validations ------------------------------------------------

echo
echo "=== 9) Negative validations ==="
echo

echo "--- Invalid type ---"
STATUS_BAD_TYPE="$(api_with_status POST "/api/v2/admin/announcements" \
  '{"title":"T","body":"B","type":"invalid"}' "$TOKEN")"
assert_http "$STATUS_BAD_TYPE" "400" "invalid type → 400"
assert_body_contains "invalid type error" ".error"

echo
echo "--- Invalid severity ---"
STATUS_BAD_SEV="$(api_with_status POST "/api/v2/admin/announcements" \
  '{"title":"T","body":"B","severity":"bad"}' "$TOKEN")"
assert_http "$STATUS_BAD_SEV" "400" "invalid severity → 400"
assert_body_contains "invalid severity error" ".error"

echo
echo "--- Missing title ---"
STATUS_NO_TITLE="$(api_with_status POST "/api/v2/admin/announcements" \
  '{"body":"Missing title"}' "$TOKEN")"
assert_http "$STATUS_NO_TITLE" "400" "missing title → 400"
assert_body_contains "missing title error" ".error"

echo
echo "--- Missing body ---"
STATUS_NO_BODY="$(api_with_status POST "/api/v2/admin/announcements" \
  '{"title":"Missing body"}' "$TOKEN")"
assert_http "$STATUS_NO_BODY" "400" "missing body → 400"
assert_body_contains "missing body error" ".error"

# ---- 10. Acknowledge on require_acknowledgement=false -----------------------

echo
echo "=== 10) Acknowledge on require_acknowledgement=false ==="
echo

STATUS_ANN2="$(api_with_status POST "/api/v2/admin/announcements" "{
  \"title\": \"No ack test $RUN_ID\",
  \"body\": \"No ack body\",
  \"type\": \"news\",
  \"severity\": \"info\",
  \"is_active\": true,
  \"require_acknowledgement\": false,
  \"track_open\": true,
  \"send_email\": false
}" "$TOKEN")"

ANN_JSON2="$(cat "$_BODY_FILE")"
echo "$ANN_JSON2" | jq
assert_http "$STATUS_ANN2" "201" "create no-ack announcement → 201"
assert_no_error "$ANN_JSON2" "create no-ack announcement"
ANN_ID2="$(echo "$ANN_JSON2" | jq -r '.id // empty')"
assert_non_empty "$ANN_ID2" "no-ack announcement id present"
assert_json_bool "$ANN_JSON2" '.require_acknowledgement' "false" "require_acknowledgement=false"

# Service raises ValueError when require_acknowledgement=false → route returns 400
STATUS_NOACK="$(api_with_status POST "/api/v2/announcements/$ANN_ID2/acknowledge" "" "$TOKEN")"
assert_http "$STATUS_NOACK" "400" "acknowledge on require_acknowledgement=false → 400"
assert_body_contains "no-ack rejection error" ".error"

# ---- 11. Soft-delete --------------------------------------------------------

echo
echo "=== 11) Soft-delete ==="
echo

STATUS_DEL="$(api_with_status DELETE "/api/v2/admin/announcements/$ANN_ID" "" "$TOKEN")"
assert_http "$STATUS_DEL" "204" "DELETE /admin/announcements/$ANN_ID → 204"

# not in admin list anymore
LIST_AFTER="$(api GET "/api/v2/admin/announcements" "" "$TOKEN")"
FOUND_IN_LIST="$(echo "$LIST_AFTER" | jq -r --arg id "$ANN_ID" \
  'map(select(.id == $id)) | length')"
[[ "$FOUND_IN_LIST" -eq 0 ]] \
  && echo "[OK] soft-deleted announcement absent from admin list" \
  || { echo "[KO] soft-deleted announcement still in admin list"; exit 1; }

# not in active user list
ACTIVE_AFTER="$(api GET "/api/v2/announcements/active" "" "$TOKEN")"
FOUND_ACTIVE="$(echo "$ACTIVE_AFTER" | jq -r --arg id "$ANN_ID" \
  'map(select(.id == $id)) | length')"
[[ "$FOUND_ACTIVE" -eq 0 ]] \
  && echo "[OK] soft-deleted announcement absent from active list" \
  || { echo "[KO] soft-deleted announcement still in active list"; exit 1; }

# tracking still accessible after soft-delete
TRACKING_DEL="$(api GET "/api/v2/admin/announcements/$ANN_ID/tracking" "" "$TOKEN")"
assert_no_error "$TRACKING_DEL" "GET tracking after soft-delete"
STATS_AFTER="$(echo "$TRACKING_DEL" | jq -r 'has("stats")')"
[[ "$STATS_AFTER" == "true" ]] || { echo "[KO] tracking stats missing after soft-delete"; exit 1; }
echo "[OK] tracking accessible after soft-delete"

# GET by id returns 404 — get_admin() excludes deleted_at IS NOT NULL
STATUS_GET_DEL="$(api_with_status GET "/api/v2/admin/announcements/$ANN_ID" "" "$TOKEN")"
assert_http "$STATUS_GET_DEL" "404" "GET soft-deleted announcement → 404"

# already soft-deleted — clear so cleanup skips it
ANN_ID=""

# ---- 12. 404 / not-found tests ----------------------------------------------

echo
echo "=== 12) 404 / not-found tests ==="
echo

UNKNOWN="unknown-00000000-0000-0000-0000-000000000000"

STATUS_404_GET="$(api_with_status GET "/api/v2/admin/announcements/$UNKNOWN" "" "$TOKEN")"
assert_http "$STATUS_404_GET" "404" "GET unknown id → 404"

STATUS_404_PATCH="$(api_with_status PATCH "/api/v2/admin/announcements/$UNKNOWN" \
  '{"title":"x"}' "$TOKEN")"
assert_http "$STATUS_404_PATCH" "404" "PATCH unknown id → 404"

STATUS_404_DEL="$(api_with_status DELETE "/api/v2/admin/announcements/$UNKNOWN" "" "$TOKEN")"
assert_http "$STATUS_404_DEL" "404" "DELETE unknown id → 404"

STATUS_404_OPEN="$(api_with_status POST "/api/v2/announcements/$UNKNOWN/open" "" "$TOKEN")"
assert_http "$STATUS_404_OPEN" "404" "POST /open unknown id → 404"

STATUS_404_READ="$(api_with_status POST "/api/v2/announcements/$UNKNOWN/read" "" "$TOKEN")"
assert_http "$STATUS_404_READ" "404" "POST /read unknown id → 404"

# mark_acknowledged returns False (not found) → 404, not 400
STATUS_404_ACK="$(api_with_status POST "/api/v2/announcements/$UNKNOWN/acknowledge" "" "$TOKEN")"
assert_http "$STATUS_404_ACK" "404" "POST /acknowledge unknown id → 404"

# ---- done -------------------------------------------------------------------

echo
echo "=== OK: announcements backend workflow passed ==="
