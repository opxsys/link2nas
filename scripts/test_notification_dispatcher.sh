#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 notification dispatcher test ==="
echo "BASE_URL=$BASE_URL"
echo

ok() {
  echo "[OK] $1"
}

ko() {
  echo "[KO] $1"
  if [[ $# -ge 2 ]]; then
    echo "$2" | jq . || echo "$2"
  fi
  exit 1
}

request_json() {
  local method="$1"
  local path="$2"
  local token="${3:-}"
  local body="${4:-}"

  if [[ -n "$body" ]]; then
    curl -s -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      ${token:+-H "X-Api-Key: $token"} \
      -d "$body"
  else
    curl -s -X "$method" "$BASE_URL$path" \
      ${token:+-H "X-Api-Key: $token"}
  fi
}

echo "1) Setup status"
SETUP="$(request_json GET /api/v2/setup/status)"
echo "$SETUP" | jq .

if [[ "$(echo "$SETUP" | jq -r '.setup_required')" == "true" ]]; then
  echo
  echo "2) Create first admin"
  CREATE_ADMIN="$(request_json POST /api/v2/setup/first-admin "" "{
    \"email\":\"$ADMIN_EMAIL\",
    \"password\":\"$ADMIN_PASSWORD\",
    \"display_name\":\"Admin\"
  }")"
  echo "$CREATE_ADMIN" | jq .
  ok "first admin created"
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
  LOGIN="$(request_json POST /api/v2/auth/login "" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
  echo "$LOGIN" | jq .
  if [[ "$(echo "$LOGIN" | jq -r 'has("error")')" == "true" ]]; then
    ko "admin login" "$LOGIN"
  fi
  TOKEN="$(echo "$LOGIN" | jq -r '.token')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    ko "admin token missing" "$LOGIN"
  fi
  ok "admin login"
fi

echo
echo "4) Dispatcher status"
STATUS="$(request_json GET /api/v2/admin/notifications/dispatcher/status "$TOKEN")"
echo "$STATUS" | jq .

if [[ "$(echo "$STATUS" | jq -r 'has("error")')" == "true" ]]; then
  ko "dispatcher status" "$STATUS"
fi

[[ "$(echo "$STATUS" | jq -r '.enabled')" == "true" ]] || ko "dispatcher enabled" "$STATUS"
ok "dispatcher status read"

echo
echo "5) Dispatcher run once"
RUN="$(request_json POST /api/v2/admin/notifications/dispatcher/run-once "$TOKEN" '{"limit":25}')"
echo "$RUN" | jq .

if [[ "$(echo "$RUN" | jq -r 'has("error")')" == "true" ]]; then
  ko "dispatcher run once" "$RUN"
fi

[[ "$(echo "$RUN" | jq -r '.processed | type')" == "number" ]] || ko "processed numeric" "$RUN"
[[ "$(echo "$RUN" | jq -r '.sent | type')" == "number" ]] || ko "sent numeric" "$RUN"
[[ "$(echo "$RUN" | jq -r '.retrying | type')" == "number" ]] || ko "retrying numeric" "$RUN"
[[ "$(echo "$RUN" | jq -r '.failed | type')" == "number" ]] || ko "failed numeric" "$RUN"
[[ "$(echo "$RUN" | jq -r '.skipped | type')" == "number" ]] || ko "skipped numeric" "$RUN"

ok "dispatcher run once"

echo
echo "6) Create notification config for dispatcher loop"
CONFIG="$(request_json POST /api/v2/notifications/configs "$TOKEN" "{
  \"name\":\"Dispatcher Test Email\",
  \"channel\":\"email\",
  \"is_enabled\":true,
  \"is_default\":false,
  \"config\":{
    \"to_email\":\"dispatcher-test@example.com\"
  }
}")"
echo "$CONFIG" | jq .

if [[ "$(echo "$CONFIG" | jq -r 'has("error")')" == "true" ]]; then
  ko "notification config created" "$CONFIG"
fi

CONFIG_ID="$(echo "$CONFIG" | jq -r '.id')"

if [[ -z "$CONFIG_ID" || "$CONFIG_ID" == "null" ]]; then
  ko "notification config id missing" "$CONFIG"
fi

ok "notification config created"

echo
echo "7) Create notification rule for dispatcher loop"
RULE="$(request_json POST /api/v2/notifications/rules "$TOKEN" "{
  \"name\":\"Dispatcher Test Rule\",
  \"config_id\":\"$CONFIG_ID\",
  \"is_enabled\":true,
  \"scope\":\"user\",
  \"severity_min\":\"error\",
  \"event_types\":[\"test.dispatcher_loop\"],
  \"rate_limit_per_hour\":30
}")"
echo "$RULE" | jq .

if [[ "$(echo "$RULE" | jq -r 'has("error")')" == "true" ]]; then
  ko "notification rule created" "$RULE"
fi

RULE_ID="$(echo "$RULE" | jq -r '.id')"

if [[ -z "$RULE_ID" || "$RULE_ID" == "null" ]]; then
  ko "notification rule id missing" "$RULE"
fi

ok "notification rule created"

echo
echo "8) Create matching notification event"
EVENT="$(request_json POST /api/v2/admin/notifications/events/test "$TOKEN" "{
  \"type\":\"test.dispatcher_loop\",
  \"severity\":\"error\",
  \"title\":\"Dispatcher loop test\",
  \"message\":\"This event should be marked sent by dispatcher\",
  \"job_id\":\"dispatcher-loop-test-job\"
}")"
echo "$EVENT" | jq .

if [[ "$(echo "$EVENT" | jq -r 'has("error")')" == "true" ]]; then
  ko "test event created" "$EVENT"
fi

EVENT_ID="$(echo "$EVENT" | jq -r '.id')"

if [[ -z "$EVENT_ID" || "$EVENT_ID" == "null" ]]; then
  ko "event id missing" "$EVENT"
fi

[[ "$(echo "$EVENT" | jq -r '.status')" == "pending" ]] || ko "event pending" "$EVENT"
echo "$EVENT" | jq -e --arg config_id "$CONFIG_ID" '.triggered_by_config_ids | index($config_id)' >/dev/null \
  || ko "event triggered by config" "$EVENT"

ok "matching event created"

echo
echo "9) Run dispatcher with matching event"
RUN_MATCH="$(request_json POST /api/v2/admin/notifications/dispatcher/run-once "$TOKEN" '{"limit":25}')"
echo "$RUN_MATCH" | jq .

if [[ "$(echo "$RUN_MATCH" | jq -r 'has("error")')" == "true" ]]; then
  ko "dispatcher run with matching event" "$RUN_MATCH"
fi

[[ "$(echo "$RUN_MATCH" | jq -r '.processed | type')" == "number" ]] || ko "processed numeric after event" "$RUN_MATCH"
[[ "$(echo "$RUN_MATCH" | jq -r '.sent | type')" == "number" ]] || ko "sent numeric after event" "$RUN_MATCH"

SENT_COUNT="$(echo "$RUN_MATCH" | jq -r '.sent')"

if [[ "$SENT_COUNT" -lt 1 ]]; then
  ko "dispatcher sent at least one event" "$RUN_MATCH"
fi

ok "dispatcher sent matching event"

echo
echo "10) Verify event is sent"
EVENTS="$(request_json GET /api/v2/notifications/events "$TOKEN")"
echo "$EVENTS" | jq .

MATCHED_STATUS="$(echo "$EVENTS" | jq -r --arg id "$EVENT_ID" '.[] | select(.id == $id) | .status' | head -n 1)"

if [[ "$MATCHED_STATUS" != "sent" ]]; then
  ko "event marked sent" "$EVENTS"
fi

ok "event marked sent"

echo
echo "11) Cleanup dispatcher test rule and config"
DELETE_RULE="$(request_json DELETE "/api/v2/notifications/rules/$RULE_ID" "$TOKEN")"
echo "$DELETE_RULE" | jq .

if [[ "$(echo "$DELETE_RULE" | jq -r '.deleted')" != "true" ]]; then
  ko "dispatcher test rule deleted" "$DELETE_RULE"
fi

DELETE_CONFIG="$(request_json DELETE "/api/v2/notifications/configs/$CONFIG_ID" "$TOKEN")"
echo "$DELETE_CONFIG" | jq .

if [[ "$(echo "$DELETE_CONFIG" | jq -r '.deleted')" != "true" ]]; then
  ko "dispatcher test config deleted" "$DELETE_CONFIG"
fi

ok "dispatcher test cleanup"



echo
echo "=== OK: notification dispatcher workflow passed ==="
