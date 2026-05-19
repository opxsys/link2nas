#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 runtime settings + dispatcher state test ==="
echo "BASE_URL=$BASE_URL"
echo

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[FAIL] Missing command: $1"
    exit 1
  }
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local message="$3"

  if [ "$actual" != "$expected" ]; then
    echo "[FAIL] $message"
    echo "       expected: $expected"
    echo "       actual:   $actual"
    exit 1
  fi

  echo "[OK] $message"
}

assert_non_empty() {
  local value="$1"
  local message="$2"

  if [ -z "$value" ] || [ "$value" = "null" ]; then
    echo "[FAIL] $message"
    exit 1
  fi

  echo "[OK] $message"
}

api_get() {
  local path="$1"
  curl -s "$BASE_URL$path" \
    -H "X-Api-Key: $TOKEN"
}

api_post_json() {
  local path="$1"
  local body="$2"
  curl -s -X POST "$BASE_URL$path" \
    -H "X-Api-Key: $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$body"
}

api_delete() {
  local path="$1"
  curl -s -X DELETE "$BASE_URL$path" \
    -H "X-Api-Key: $TOKEN"
}

require_cmd curl
require_cmd jq

echo "1) Setup status"
SETUP_STATUS="$(curl -s "$BASE_URL/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq

SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [ "$SETUP_REQUIRED" = "true" ]; then
  echo
  echo "2) Create first admin"
  CREATE_ADMIN="$(curl -s -X POST "$BASE_URL/api/v2/setup/first-admin" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\":\"$ADMIN_EMAIL\",
      \"password\":\"$ADMIN_PASSWORD\",
      \"display_name\":\"Admin\"
    }")"
  echo "$CREATE_ADMIN" | jq
  echo "[OK] first admin created"
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
  LOGIN="$(curl -s -X POST "$BASE_URL/api/v2/auth/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\":\"$ADMIN_EMAIL\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  echo "$LOGIN" | jq
  TOKEN="$(echo "$LOGIN" | jq -r '.token')"
  assert_non_empty "$TOKEN" "token received"
fi

echo
echo "4) Read runtime settings"
RUNTIME="$(api_get "/api/v2/admin/app-settings/runtime")"
echo "$RUNTIME" | jq

NOTIF_ENABLED="$(echo "$RUNTIME" | jq -r '.notifications.dispatcher.enabled')"
NOTIF_INTERVAL="$(echo "$RUNTIME" | jq -r '.notifications.dispatcher.interval_seconds')"
NOTIF_LIMIT="$(echo "$RUNTIME" | jq -r '.notifications.dispatcher.limit')"

JOBS_ENABLED="$(echo "$RUNTIME" | jq -r '.jobs.orchestrator.enabled')"
JOBS_INTERVAL="$(echo "$RUNTIME" | jq -r '.jobs.orchestrator.interval_seconds')"
JOBS_MAX="$(echo "$RUNTIME" | jq -r '.jobs.orchestrator.max_jobs_per_run')"

LOCAL_ENABLED="$(echo "$RUNTIME" | jq -r '.downloads.local_worker.enabled')"
LOCAL_INTERVAL="$(echo "$RUNTIME" | jq -r '.downloads.local_worker.poll_interval_seconds')"
LOCAL_MAX="$(echo "$RUNTIME" | jq -r '.downloads.local_worker.max_concurrent_downloads')"

assert_non_empty "$NOTIF_ENABLED" "notifications.dispatcher.enabled present"
assert_non_empty "$NOTIF_INTERVAL" "notifications.dispatcher.interval_seconds present"
assert_non_empty "$NOTIF_LIMIT" "notifications.dispatcher.limit present"

assert_non_empty "$JOBS_ENABLED" "jobs.orchestrator.enabled present"
assert_non_empty "$JOBS_INTERVAL" "jobs.orchestrator.interval_seconds present"
assert_non_empty "$JOBS_MAX" "jobs.orchestrator.max_jobs_per_run present"

assert_non_empty "$LOCAL_ENABLED" "downloads.local_worker.enabled present"
assert_non_empty "$LOCAL_INTERVAL" "downloads.local_worker.poll_interval_seconds present"
assert_non_empty "$LOCAL_MAX" "downloads.local_worker.max_concurrent_downloads present"

echo
echo "5) Dispatcher status"
DISPATCHER_STATUS="$(api_get "/api/v2/admin/notifications/dispatcher/status")"
echo "$DISPATCHER_STATUS" | jq

DISPATCHER_ENABLED="$(echo "$DISPATCHER_STATUS" | jq -r '.enabled')"
DISPATCHER_MESSAGE="$(echo "$DISPATCHER_STATUS" | jq -r '.message')"

assert_non_empty "$DISPATCHER_ENABLED" "dispatcher enabled field present"
assert_non_empty "$DISPATCHER_MESSAGE" "dispatcher message present"

echo
echo "6) Admin notification events list"
EVENTS="$(api_get "/api/v2/admin/notifications/events?limit=50")"
echo "$EVENTS" | jq 'if type == "array" then {count:length} else . end'

EVENTS_TYPE="$(echo "$EVENTS" | jq -r 'type')"
assert_eq "$EVENTS_TYPE" "array" "admin events endpoint returns array"

echo
echo "7) Admin notification events filters"
SENT_EVENTS="$(api_get "/api/v2/admin/notifications/events?limit=50&status=sent")"
FAILED_EVENTS="$(api_get "/api/v2/admin/notifications/events?limit=50&status=failed")"
RETRYING_EVENTS="$(api_get "/api/v2/admin/notifications/events?limit=50&status=retrying")"

assert_eq "$(echo "$SENT_EVENTS" | jq -r 'type')" "array" "status=sent returns array"
assert_eq "$(echo "$FAILED_EVENTS" | jq -r 'type')" "array" "status=failed returns array"
assert_eq "$(echo "$RETRYING_EVENTS" | jq -r 'type')" "array" "status=retrying returns array"

echo "[OK] notification event filters are valid"

echo
echo "8) Max attempts dispatcher behavior"

CONFIG=""
RULE=""
EVENT=""
CONFIG_ID=""
RULE_ID=""
EVENT_ID=""

cleanup() {
  set +e

  if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
    api_delete "/api/v2/notifications/rules/$RULE_ID" >/dev/null
  fi

  if [ -n "${CONFIG_ID:-}" ] && [ "$CONFIG_ID" != "null" ]; then
    api_delete "/api/v2/notifications/configs/$CONFIG_ID" >/dev/null
  fi
}
trap cleanup EXIT

echo
echo "8.1) Create temporary notification config"
CONFIG="$(api_post_json "/api/v2/notifications/configs" '{
  "name":"Runtime max attempts isolated",
  "channel":"email",
  "is_enabled":true,
  "is_default":false,
  "config":{
    "to_email":"nobody@example.com"
  }
}')"

echo "$CONFIG" | jq
CONFIG_ID="$(echo "$CONFIG" | jq -r '.id')"
assert_non_empty "$CONFIG_ID" "temporary config created"

echo
echo "8.2) Create isolated notification rule"
RULE="$(api_post_json "/api/v2/notifications/rules" "{
  \"name\":\"Runtime max attempts isolated rule\",
  \"config_id\":\"$CONFIG_ID\",
  \"is_enabled\":true,
  \"scope\":\"user\",
  \"severity_min\":\"error\",
  \"event_types\":[\"test.runtime_max_attempts\"],
  \"rate_limit_per_hour\":30
}")"

echo "$RULE" | jq
RULE_ID="$(echo "$RULE" | jq -r '.id')"
assert_non_empty "$RULE_ID" "temporary rule created"

echo
echo "8.3) Create isolated event"
EVENT="$(api_post_json "/api/v2/admin/notifications/events/test" '{
  "type":"test.runtime_max_attempts",
  "severity":"error",
  "title":"Runtime max attempts test",
  "message":"This event should retry until max_attempts=5.",
  "job_id":"runtime-max-attempts-test"
}')"

echo "$EVENT" | jq '{id, status, attempts, max_attempts, triggered_by_config_ids, triggered_by_rule_ids}'
EVENT_ID="$(echo "$EVENT" | jq -r '.id')"
EVENT_MAX_ATTEMPTS="$(echo "$EVENT" | jq -r '.max_attempts')"
CONFIG_TRIGGER_COUNT="$(echo "$EVENT" | jq '.triggered_by_config_ids | length')"

assert_non_empty "$EVENT_ID" "temporary event created"
assert_eq "$EVENT_MAX_ATTEMPTS" "5" "event max_attempts is 5"
assert_eq "$CONFIG_TRIGGER_COUNT" "1" "event has one isolated config trigger"

echo
echo "8.4) Delete config to force dispatcher failure"
DELETE_CONFIG="$(api_delete "/api/v2/notifications/configs/$CONFIG_ID")"
echo "$DELETE_CONFIG" | jq

DELETED="$(echo "$DELETE_CONFIG" | jq -r '.deleted')"
assert_eq "$DELETED" "true" "temporary config deleted"

# Prevent cleanup from trying to delete it again.
CONFIG_ID=""

check_event_state() {
  local expected_attempts="$1"
  local expected_status="$2"

  CURRENT="$(api_get "/api/v2/admin/notifications/events?limit=100" \
    | jq ".[] | select(.id==\"$EVENT_ID\") | {attempts, max_attempts, status, last_error}")"

  echo "$CURRENT" | jq

  ACTUAL_ATTEMPTS="$(echo "$CURRENT" | jq -r '.attempts')"
  ACTUAL_MAX_ATTEMPTS="$(echo "$CURRENT" | jq -r '.max_attempts')"
  ACTUAL_STATUS="$(echo "$CURRENT" | jq -r '.status')"
  ACTUAL_ERROR="$(echo "$CURRENT" | jq -r '.last_error')"

  assert_eq "$ACTUAL_ATTEMPTS" "$expected_attempts" "attempts=$expected_attempts"
  assert_eq "$ACTUAL_MAX_ATTEMPTS" "5" "max_attempts remains 5"
  assert_eq "$ACTUAL_STATUS" "$expected_status" "status=$expected_status"
  assert_non_empty "$ACTUAL_ERROR" "last_error present"
}

echo
echo "8.5) Dispatcher pass 1"
api_post_json "/api/v2/admin/notifications/dispatcher/run-once" '{"limit":25}' | jq
check_event_state "1" "retrying"

echo
echo "8.6) Dispatcher passes 2 to 5"
for i in 2 3 4 5; do
  echo "PASS $i"
  api_post_json "/api/v2/admin/notifications/dispatcher/run-once" '{"limit":25}' >/dev/null

  if [ "$i" -lt 5 ]; then
    check_event_state "$i" "retrying"
  else
    check_event_state "$i" "failed"
  fi
done

echo
echo "8.7) Failed event must not be processed again"
api_post_json "/api/v2/admin/notifications/dispatcher/run-once" '{"limit":25}' >/dev/null
check_event_state "5" "failed"

echo
echo "9) Cleanup temporary rule"
DELETE_RULE="$(api_delete "/api/v2/notifications/rules/$RULE_ID")"
echo "$DELETE_RULE" | jq

RULE_DELETED="$(echo "$DELETE_RULE" | jq -r '.deleted // false')"
RULE_ERROR="$(echo "$DELETE_RULE" | jq -r '.error // ""')"

if [ "$RULE_DELETED" = "true" ]; then
  echo "[OK] temporary rule deleted"
elif [ "$RULE_ERROR" = "Notification rule not found" ]; then
  echo "[OK] temporary rule already deleted"
else
  echo "[FAIL] temporary rule cleanup failed"
  echo "$DELETE_RULE" | jq
  exit 1
fi

RULE_ID=""

echo
echo "=== OK: runtime settings + dispatcher state workflow passed ==="
