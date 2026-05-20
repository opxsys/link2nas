#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 notification trigger dedup test ==="
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

  if [[ "$(echo "$CREATE_ADMIN" | jq -r 'has("error")')" == "true" ]]; then
    ko "first admin created" "$CREATE_ADMIN"
  fi

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
echo "4) Create one notification config"
CONFIG="$(request_json POST /api/v2/notifications/configs "$TOKEN" "{
  \"name\":\"Dedup Test Email\",
  \"channel\":\"email\",
  \"is_enabled\":true,
  \"is_default\":false,
  \"config\":{
    \"to_email\":\"dedup-test@example.com\"
  }
}")"
echo "$CONFIG" | jq .

if [[ "$(echo "$CONFIG" | jq -r 'has("error")')" == "true" ]]; then
  ko "notification config created" "$CONFIG"
fi

CONFIG_ID="$(echo "$CONFIG" | jq -r '.id')"

if [[ -z "$CONFIG_ID" || "$CONFIG_ID" == "null" ]]; then
  ko "config id missing" "$CONFIG"
fi

ok "notification config created"

echo
echo "5) Create three matching rules pointing to the same config"
RULE_IDS=()

for i in 1 2 3; do
  RULE="$(request_json POST /api/v2/notifications/rules "$TOKEN" "{
    \"name\":\"Dedup Test Rule $i\",
    \"config_id\":\"$CONFIG_ID\",
    \"is_enabled\":true,
    \"scope\":\"user\",
    \"severity_min\":\"error\",
    \"event_types\":[\"test.dedup\"],
    \"rate_limit_per_hour\":30
  }")"

  echo "$RULE" | jq .

  if [[ "$(echo "$RULE" | jq -r 'has("error")')" == "true" ]]; then
    ko "rule $i created" "$RULE"
  fi

  RULE_ID="$(echo "$RULE" | jq -r '.id')"

  if [[ -z "$RULE_ID" || "$RULE_ID" == "null" ]]; then
    ko "rule $i id missing" "$RULE"
  fi

  RULE_IDS+=("$RULE_ID")
done

ok "three matching rules created"

echo
echo "6) Create matching event"
EVENT="$(request_json POST /api/v2/admin/notifications/events/test "$TOKEN" "{
  \"type\":\"test.dedup\",
  \"severity\":\"error\",
  \"title\":\"Dedup test event\",
  \"message\":\"This event should contain unique config ids\",
  \"job_id\":\"dedup-test-job\"
}")"
echo "$EVENT" | jq .

if [[ "$(echo "$EVENT" | jq -r 'has("error")')" == "true" ]]; then
  ko "event created" "$EVENT"
fi

EVENT_ID="$(echo "$EVENT" | jq -r '.id')"

if [[ -z "$EVENT_ID" || "$EVENT_ID" == "null" ]]; then
  ko "event id missing" "$EVENT"
fi

ok "event created"

echo
echo "7) Check rule triggers count"
RULE_TRIGGER_COUNT="$(echo "$EVENT" | jq '.triggered_by_rule_ids | length')"

if [[ "$RULE_TRIGGER_COUNT" -lt 3 ]]; then
  ko "expected at least 3 rule triggers" "$EVENT"
fi

ok "event matched multiple rules"

echo
echo "8) Check config trigger deduplication"
CONFIG_TRIGGER_COUNT="$(echo "$EVENT" | jq '.triggered_by_config_ids | length')"
UNIQUE_CONFIG_TRIGGER_COUNT="$(echo "$EVENT" | jq '.triggered_by_config_ids | unique | length')"
MATCHING_CONFIG_COUNT="$(echo "$EVENT" | jq --arg config_id "$CONFIG_ID" '[.triggered_by_config_ids[] | select(. == $config_id)] | length')"

echo "CONFIG_TRIGGER_COUNT=$CONFIG_TRIGGER_COUNT"
echo "UNIQUE_CONFIG_TRIGGER_COUNT=$UNIQUE_CONFIG_TRIGGER_COUNT"
echo "MATCHING_CONFIG_COUNT=$MATCHING_CONFIG_COUNT"

if [[ "$CONFIG_TRIGGER_COUNT" != "$UNIQUE_CONFIG_TRIGGER_COUNT" ]]; then
  echo "[KO] duplicate config ids detected"
  echo "$EVENT" | jq '.triggered_by_config_ids'
  DUPLICATES_DETECTED="true"
else
  DUPLICATES_DETECTED="false"
  ok "config ids are unique"
fi

echo
echo "8b) Mark dedup test event as sent through dispatcher"
RUN_DISPATCHER="$(request_json POST /api/v2/admin/notifications/dispatcher/run-once "$TOKEN" '{"limit":25}')"
echo "$RUN_DISPATCHER" | jq .

if [[ "$(echo "$RUN_DISPATCHER" | jq -r 'has("error")')" == "true" ]]; then
  ko "dispatcher run for dedup event" "$RUN_DISPATCHER"
fi

SENT_COUNT="$(echo "$RUN_DISPATCHER" | jq -r '.sent')"

if [[ "$SENT_COUNT" -lt 1 ]]; then
  ko "dispatcher sent dedup event" "$RUN_DISPATCHER"
fi

ok "dedup event marked sent"
echo
echo "9) Cleanup"
for RULE_ID in "${RULE_IDS[@]}"; do
  DELETE_RULE="$(request_json DELETE "/api/v2/notifications/rules/$RULE_ID" "$TOKEN")"
  echo "$DELETE_RULE" | jq .

  if [[ "$(echo "$DELETE_RULE" | jq -r '.deleted')" != "true" ]]; then
    ko "rule deleted" "$DELETE_RULE"
  fi
done

DELETE_CONFIG="$(request_json DELETE "/api/v2/notifications/configs/$CONFIG_ID" "$TOKEN")"
echo "$DELETE_CONFIG" | jq .

if [[ "$(echo "$DELETE_CONFIG" | jq -r '.deleted')" != "true" ]]; then
  ko "config deleted" "$DELETE_CONFIG"
fi

ok "cleanup done"

echo
if [[ "$DUPLICATES_DETECTED" == "true" ]]; then
  echo "=== KO: duplicate notification config triggers detected ==="
  exit 1
fi

echo "=== OK: notification config triggers are deduplicated ==="
