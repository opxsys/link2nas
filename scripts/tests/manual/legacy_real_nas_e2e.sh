#!/bin/bash

set -e

########################################
# CONFIG
########################################

BASE_URL="http://127.0.0.1:5000"

MAGNET_LINK="magnet:?xt=urn:btih:e15050d9b20cd622212d3aecd253790bf9602732"
RD_API_KEY="${RD_API_KEY:?RD_API_KEY is required}"

SYNO_URL="${SYNO_URL:?SYNO_URL is required}"
SYNO_USER="${SYNO_USER:?SYNO_USER is required}"
SYNO_PASSWORD="${SYNO_PASSWORD:?SYNO_PASSWORD is required}"
SYNO_VERIFY_SSL=false
SYNO_DESTINATION_BASE="downloads"

API_KEY_HEADER="X-Api-Key"

########################################
# HELPERS
########################################

print_json() {
  echo "$1" | jq
}

assert_json_field_equals() {
  local json="$1"
  local field="$2"
  local expected="$3"

  local actual
  actual=$(echo "$json" | jq -r "$field")

  if [ "$actual" != "$expected" ]; then
    echo "ASSERT FAILED: $field expected [$expected], got [$actual]"
    echo "$json" | jq
    exit 1
  fi
}

assert_json_array_contains() {
  local json="$1"
  local field="$2"
  local expected="$3"

  local found
  found=$(echo "$json" | jq -r "$field | index(\"$expected\") != null")

  if [ "$found" != "true" ]; then
    echo "ASSERT FAILED: $field does not contain [$expected]"
    echo "$json" | jq
    exit 1
  fi
}

assert_json_array_empty() {
  local json="$1"
  local field="$2"

  local length
  length=$(echo "$json" | jq -r "$field | length")

  if [ "$length" != "0" ]; then
    echo "ASSERT FAILED: $field expected empty array"
    echo "$json" | jq
    exit 1
  fi
}

post_json() {
  local url="$1"
  local body="$2"

  curl -s -X POST "$url" \
    -H "Content-Type: application/json" \
    -H "$API_KEY_HEADER: $TOKEN" \
    -d "$body"
}

post_empty() {
  local url="$1"

  curl -s -X POST "$url" \
    -H "$API_KEY_HEADER: $TOKEN"
}

get_auth() {
  local url="$1"

  curl -s -H "$API_KEY_HEADER: $TOKEN" "$url"
}

########################################
# CREATE USER
########################################

echo "=== CREATE USER ==="
USER_JSON=$(curl -s -X POST "$BASE_URL/api/v2/dev/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"v2-nas-e2e@test.com","display_name":"V2 NAS E2E Test"}')

print_json "$USER_JSON"

USER_ID=$(echo "$USER_JSON" | jq -r '.id')
[ -z "$USER_ID" ] || [ "$USER_ID" = "null" ] && { echo "ERROR USER"; exit 1; }

echo "USER_ID=$USER_ID"

########################################
# CREATE TOKEN
########################################

echo "=== CREATE TOKEN ==="
TOKEN_JSON=$(curl -s -X POST "$BASE_URL/api/v2/dev/users/$USER_ID/tokens" \
  -H "Content-Type: application/json" \
  -d '{"label":"nas e2e test token"}')

print_json "$TOKEN_JSON"

TOKEN=$(echo "$TOKEN_JSON" | jq -r '.token')
[ -z "$TOKEN" ] || [ "$TOKEN" = "null" ] && { echo "ERROR TOKEN"; exit 1; }

echo "TOKEN=$TOKEN"

########################################
# CONFIG PROVIDER
########################################

echo "=== CONFIG PROVIDER ==="
PROVIDER_JSON=$(post_json "$BASE_URL/api/v2/providers" "{
  \"provider_name\":\"realdebrid\",
  \"encrypted_api_key\":\"$RD_API_KEY\",
  \"is_default\":true
}")

print_json "$PROVIDER_JSON"
assert_json_field_equals "$PROVIDER_JSON" '.provider_name' "realdebrid"
assert_json_field_equals "$PROVIDER_JSON" '.has_api_key' "true"
assert_json_field_equals "$PROVIDER_JSON" '.is_default' "true"

########################################
# CONFIG NAS DESTINATION
########################################

echo "=== CONFIG NAS DESTINATION ==="
NAS_CONFIG=$(jq -nc \
  --arg url "$SYNO_URL" \
  --arg username "$SYNO_USER" \
  --arg password "$SYNO_PASSWORD" \
  --arg destination_base "$SYNO_DESTINATION_BASE" \
  --argjson verify_ssl "$SYNO_VERIFY_SSL" \
  '{
    synology_url: $url,
    username: $username,
    password: $password,
    verify_ssl: $verify_ssl,
    destination_base: $destination_base
  }'
)

NAS_DEST_JSON=$(post_json "$BASE_URL/api/v2/destinations" "$(jq -nc \
  --arg config "$NAS_CONFIG" \
  '{
    destination_name: "nas",
    config_json: $config,
    is_default: true
  }'
)")

print_json "$NAS_DEST_JSON"
assert_json_field_equals "$NAS_DEST_JSON" '.destination_name' "nas"
assert_json_field_equals "$NAS_DEST_JSON" '.is_default' "true"
assert_json_field_equals "$NAS_DEST_JSON" '.config.has_password' "true"

########################################
# SETTINGS TESTS
########################################

echo "=== SETTINGS SUMMARY ==="
SETTINGS_JSON=$(get_auth "$BASE_URL/api/v2/settings")
print_json "$SETTINGS_JSON"

echo "=== PROVIDER TEST ==="
PROVIDER_TEST_JSON=$(post_empty "$BASE_URL/api/v2/settings/provider/test")
print_json "$PROVIDER_TEST_JSON"
assert_json_field_equals "$PROVIDER_TEST_JSON" '.ok' "true"

echo "=== DESTINATION TEST ==="
DEST_TEST_JSON=$(post_empty "$BASE_URL/api/v2/settings/destination/test")
print_json "$DEST_TEST_JSON"
assert_json_field_equals "$DEST_TEST_JSON" '.ok' "true"
assert_json_field_equals "$DEST_TEST_JSON" '.destination_name' "nas"

########################################
# EXTERNAL NAS CHECK
########################################

echo "=== CHECK NAS ACCESSIBILITY ==="

NAS_AUTH_URL="${SYNO_URL%/}/webapi/auth.cgi"
NAS_TASK_URL="${SYNO_URL%/}/webapi/DownloadStation/task.cgi"

echo "NAS_AUTH_URL=$NAS_AUTH_URL"
echo "NAS_TASK_URL=$NAS_TASK_URL"

if [ "$SYNO_VERIFY_SSL" = "false" ]; then
  CURL_SSL_OPT="-k"
else
  CURL_SSL_OPT=""
fi

echo "--- HTTP reachability ---"
curl -sS -i $CURL_SSL_OPT \
  --connect-timeout 5 \
  --max-time 10 \
  "$NAS_AUTH_URL" | head -n 5

echo "--- DSM login test ---"
NAS_LOGIN_RESPONSE=$(curl -sS $CURL_SSL_OPT \
  --connect-timeout 5 \
  --max-time 10 \
  -X POST "$NAS_AUTH_URL" \
  -d "api=SYNO.API.Auth" \
  -d "version=3" \
  -d "method=login" \
  -d "account=$SYNO_USER" \
  -d "passwd=$SYNO_PASSWORD" \
  -d "session=DownloadStation" \
  -d "format=sid")

print_json "$NAS_LOGIN_RESPONSE"

NAS_LOGIN_SUCCESS=$(echo "$NAS_LOGIN_RESPONSE" | jq -r '.success // false')

if [ "$NAS_LOGIN_SUCCESS" != "true" ]; then
  echo "ERROR: NAS login failed"
  exit 1
fi

NAS_SID=$(echo "$NAS_LOGIN_RESPONSE" | jq -r '.data.sid // empty')

if [ -z "$NAS_SID" ]; then
  echo "ERROR: NAS SID missing"
  exit 1
fi

echo "NAS login OK"

echo "--- Download Station API test ---"
NAS_DS_RESPONSE=$(curl -sS $CURL_SSL_OPT \
  --connect-timeout 5 \
  --max-time 10 \
  "$NAS_TASK_URL" \
  -d "api=SYNO.DownloadStation.Task" \
  -d "version=1" \
  -d "method=list" \
  -d "_sid=$NAS_SID")

print_json "$NAS_DS_RESPONSE"

NAS_DS_SUCCESS=$(echo "$NAS_DS_RESPONSE" | jq -r '.success // false')

if [ "$NAS_DS_SUCCESS" != "true" ]; then
  echo "ERROR: Download Station API not accessible"
  exit 1
fi

echo "Download Station API OK"

echo "--- DSM logout ---"
curl -sS $CURL_SSL_OPT \
  --connect-timeout 5 \
  --max-time 10 \
  -X POST "$NAS_AUTH_URL" \
  -d "api=SYNO.API.Auth" \
  -d "version=3" \
  -d "method=logout" \
  -d "session=DownloadStation" \
  -d "_sid=$NAS_SID" | jq || true

########################################
# CREATE JOB
########################################

echo "=== CREATE JOB ==="
JOB_JSON=$(post_json "$BASE_URL/api/v2/jobs" "{
  \"source_type\":\"magnet\",
  \"source_value\":\"$MAGNET_LINK\",
  \"provider_name\":\"realdebrid\"
}")

print_json "$JOB_JSON"

JOB_ID=$(echo "$JOB_JSON" | jq -r '.id')
[ -z "$JOB_ID" ] || [ "$JOB_ID" = "null" ] && { echo "ERROR JOB"; exit 1; }

assert_json_field_equals "$JOB_JSON" '.status' "created"
assert_json_array_contains "$JOB_JSON" '.allowed_actions' "start"

echo "JOB_ID=$JOB_ID"

########################################
# NEGATIVE ACTION TESTS BEFORE START
########################################

echo "=== NEGATIVE: RESEND FROM CREATED MUST FAIL ==="
RESEND_CREATED_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/resend")
print_json "$RESEND_CREATED_JSON"
assert_json_field_equals "$RESEND_CREATED_JSON" '.error' "Action 'resend' is not allowed from status 'created'"

echo "=== NEGATIVE: SEND FROM CREATED MUST FAIL ==="
SEND_CREATED_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/send-to-destination")
print_json "$SEND_CREATED_JSON"
assert_json_field_equals "$SEND_CREATED_JSON" '.error' "Action 'send_to_destination' is not allowed from status 'created'"

########################################
# FLOW
########################################

echo "=== START ==="
START_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/start")
print_json "$START_JSON"
assert_json_field_equals "$START_JSON" '.status' "started"
assert_json_field_equals "$START_JSON" '.provider_name' "realdebrid"
assert_json_array_contains "$START_JSON" '.allowed_actions' "refresh"

sleep 2

echo "=== REFRESH TO WAITING_FILES_SELECTION ==="
REFRESH_1_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/refresh")
print_json "$REFRESH_1_JSON"
assert_json_field_equals "$REFRESH_1_JSON" '.status' "waiting_files_selection"
assert_json_array_contains "$REFRESH_1_JSON" '.allowed_actions' "select_files"

echo "=== NEGATIVE: UNRESTRICT BEFORE DOWNLOADED MUST FAIL ==="
UNRESTRICT_EARLY_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/unrestrict")
print_json "$UNRESTRICT_EARLY_JSON"
assert_json_field_equals "$UNRESTRICT_EARLY_JSON" '.error' "Action 'unrestrict' is not allowed from status 'waiting_files_selection'"

echo "=== SELECT FILE ==="
SELECT_JSON=$(post_json "$BASE_URL/api/v2/jobs/$JOB_ID/select-files" '{"files":"1"}')
print_json "$SELECT_JSON"
assert_json_field_equals "$SELECT_JSON" '.status' "downloading"
assert_json_array_contains "$SELECT_JSON" '.allowed_actions' "refresh"

sleep 2

echo "=== REFRESH TO DOWNLOADED ==="
REFRESH_2_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/refresh")
print_json "$REFRESH_2_JSON"
assert_json_field_equals "$REFRESH_2_JSON" '.status' "downloaded"
assert_json_array_contains "$REFRESH_2_JSON" '.allowed_actions' "unrestrict"

echo "=== UNRESTRICT ==="
UNRESTRICT_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/unrestrict")
print_json "$UNRESTRICT_JSON"
assert_json_field_equals "$UNRESTRICT_JSON" '.status' "ready"
assert_json_array_contains "$UNRESTRICT_JSON" '.allowed_actions' "send_to_destination"

echo "=== NEGATIVE: RESEND FROM READY MUST FAIL ==="
RESEND_READY_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/resend")
print_json "$RESEND_READY_JSON"
assert_json_field_equals "$RESEND_READY_JSON" '.error' "Action 'resend' is not allowed from status 'ready'"

echo "=== SEND TO NAS ==="
SEND_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/send-to-destination")
print_json "$SEND_JSON"
assert_json_field_equals "$SEND_JSON" '.status' "completed"
assert_json_field_equals "$SEND_JSON" '.destination_name' "nas"
assert_json_array_contains "$SEND_JSON" '.allowed_actions' "resend"

echo "=== RESEND TO NAS ==="
RESEND_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$JOB_ID/resend")
print_json "$RESEND_JSON"
assert_json_field_equals "$RESEND_JSON" '.status' "completed"
assert_json_field_equals "$RESEND_JSON" '.destination_name' "nas"
assert_json_array_contains "$RESEND_JSON" '.allowed_actions' "resend"

echo "=== FINAL JOB CHECK ==="
FINAL_JOB_JSON=$(get_auth "$BASE_URL/api/v2/jobs/$JOB_ID")
print_json "$FINAL_JOB_JSON"
assert_json_field_equals "$FINAL_JOB_JSON" '.status' "completed"
assert_json_field_equals "$FINAL_JOB_JSON" '.provider_name' "realdebrid"
assert_json_field_equals "$FINAL_JOB_JSON" '.destination_name' "nas"
assert_json_array_contains "$FINAL_JOB_JSON" '.allowed_actions' "resend"


sqlite3 data/link2nas_v2.sqlite3 "
UPDATE jobs
SET output_links_json='[{\"url\":\"https://real-debrid.com/dead-link-test\",\"filename\":\"dead.mkv\"}]'
WHERE id='$JOB_ID';
"

echo "=== RESEND WITH REBUILD ==="
curl -s -X POST -H "X-Api-Key: $TOKEN" \
$BASE_URL/api/v2/jobs/$JOB_ID/resend | jq


########################################
# API VALIDATION CHECKS
########################################

echo "=== LIST DESTINATIONS ==="
DESTINATIONS_JSON=$(get_auth "$BASE_URL/api/v2/destinations")
print_json "$DESTINATIONS_JSON"

echo "=== NEGATIVE: INVALID NAS CONFIG ==="
INVALID_NAS_JSON=$(post_json "$BASE_URL/api/v2/destinations" '{"destination_name":"nas","config_json":"{}","is_default":true}')
print_json "$INVALID_NAS_JSON"
assert_json_field_equals "$INVALID_NAS_JSON" '.error' "nas destination requires synology_url"

echo "=== LIST PROVIDERS ==="
PROVIDERS_JSON=$(get_auth "$BASE_URL/api/v2/providers")
print_json "$PROVIDERS_JSON"

echo "=== NEGATIVE: INVALID PROVIDER ==="
INVALID_PROVIDER_JSON=$(post_json "$BASE_URL/api/v2/providers" '{"provider_name":"fake"}')
print_json "$INVALID_PROVIDER_JSON"
assert_json_field_equals "$INVALID_PROVIDER_JSON" '.error' "invalid provider_name"

echo "=== DONE E2E TEST ==="

########################################
# RESTART TEST
########################################

echo "=== FORCE FAILED (manual DB hack) ==="

sqlite3 data/link2nas_v2.sqlite3 "
UPDATE jobs
SET status='failed', error_message='forced failure'
WHERE id='$JOB_ID';
"

echo "=== CHECK FAILED STATE ==="
curl -s -H "X-Api-Key: $TOKEN" \
$BASE_URL/api/v2/jobs/$JOB_ID | jq

echo "=== RESTART ==="
curl -s -X POST \
-H "X-Api-Key: $TOKEN" \
$BASE_URL/api/v2/jobs/$JOB_ID/restart | jq

echo "=== CHECK AFTER RESTART ==="
curl -s -H "X-Api-Key: $TOKEN" \
$BASE_URL/api/v2/jobs/$JOB_ID | jq

########################################
# CANCEL TEST
########################################

echo "=== CREATE JOB FOR CANCEL ==="
CANCEL_JOB_JSON=$(post_json "$BASE_URL/api/v2/jobs" "{
  \"source_type\":\"magnet\",
  \"source_value\":\"$MAGNET_LINK\",
  \"provider_name\":\"realdebrid\"
}")

print_json "$CANCEL_JOB_JSON"

CANCEL_JOB_ID=$(echo "$CANCEL_JOB_JSON" | jq -r '.id')
[ -z "$CANCEL_JOB_ID" ] || [ "$CANCEL_JOB_ID" = "null" ] && { echo "ERROR CANCEL JOB"; exit 1; }

assert_json_field_equals "$CANCEL_JOB_JSON" '.status' "created"
assert_json_array_contains "$CANCEL_JOB_JSON" '.allowed_actions' "cancel"

echo "=== CANCEL CREATED JOB ==="
CANCEL_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$CANCEL_JOB_ID/cancel")
print_json "$CANCEL_JSON"

assert_json_field_equals "$CANCEL_JSON" '.status' "cancelled"
assert_json_array_contains "$CANCEL_JSON" '.allowed_actions' "restart"

echo "=== NEGATIVE: START CANCELLED JOB MUST FAIL ==="
START_CANCELLED_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$CANCEL_JOB_ID/start")
print_json "$START_CANCELLED_JSON"

assert_json_field_equals "$START_CANCELLED_JSON" '.error' "Action 'start' is not allowed from status 'cancelled'"

echo "=== RESTART CANCELLED JOB ==="
RESTART_CANCELLED_JSON=$(post_empty "$BASE_URL/api/v2/jobs/$CANCEL_JOB_ID/restart")
print_json "$RESTART_CANCELLED_JSON"

assert_json_field_equals "$RESTART_CANCELLED_JSON" '.status' "created"
assert_json_array_contains "$RESTART_CANCELLED_JSON" '.allowed_actions' "start"

########################################
# DELETE TEST
########################################

echo "=== CREATE JOB FOR DELETE ==="
DELETE_JOB_JSON=$(post_json "$BASE_URL/api/v2/jobs" "{
  \"source_type\":\"magnet\",
  \"source_value\":\"$MAGNET_LINK\",
  \"provider_name\":\"realdebrid\"
}")

print_json "$DELETE_JOB_JSON"

DELETE_JOB_ID=$(echo "$DELETE_JOB_JSON" | jq -r '.id')
[ -z "$DELETE_JOB_ID" ] || [ "$DELETE_JOB_ID" = "null" ] && { echo "ERROR DELETE JOB"; exit 1; }

echo "=== DELETE JOB ==="
DELETE_HTTP_CODE=$(curl -s -o /tmp/link2nas_delete_response.txt -w "%{http_code}" \
  -X DELETE \
  -H "X-Api-Key: $TOKEN" \
  "$BASE_URL/api/v2/jobs/$DELETE_JOB_ID")

cat /tmp/link2nas_delete_response.txt || true
echo
echo "HTTP_CODE=$DELETE_HTTP_CODE"

if [ "$DELETE_HTTP_CODE" != "204" ]; then
  echo "ERROR: DELETE expected 204"
  exit 1
fi

echo "=== GET DELETED JOB MUST 404 ==="
GET_DELETED_HTTP_CODE=$(curl -s -o /tmp/link2nas_get_deleted_response.txt -w "%{http_code}" \
  -H "X-Api-Key: $TOKEN" \
  "$BASE_URL/api/v2/jobs/$DELETE_JOB_ID")

cat /tmp/link2nas_get_deleted_response.txt | jq || true
echo "HTTP_CODE=$GET_DELETED_HTTP_CODE"

if [ "$GET_DELETED_HTTP_CODE" != "404" ]; then
  echo "ERROR: GET deleted job expected 404"
  exit 1
fi

echo "=== DELETE UNKNOWN JOB MUST 404 ==="
DELETE_UNKNOWN_HTTP_CODE=$(curl -s -o /tmp/link2nas_delete_unknown_response.txt -w "%{http_code}" \
  -X DELETE \
  -H "X-Api-Key: $TOKEN" \
  "$BASE_URL/api/v2/jobs/unknown-job-id")

cat /tmp/link2nas_delete_unknown_response.txt | jq || true
echo "HTTP_CODE=$DELETE_UNKNOWN_HTTP_CODE"

if [ "$DELETE_UNKNOWN_HTTP_CODE" != "404" ]; then
  echo "ERROR: DELETE unknown job expected 404"
  exit 1
fi

