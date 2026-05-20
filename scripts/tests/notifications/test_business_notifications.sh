#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"
TEST_EMAIL_DOMAIN="${TEST_EMAIL_DOMAIN:-test.local}"

echo "=== Link2NAS V2 business notifications test ==="
echo "Backend=${V2_DATABASE_BACKEND:-sqlite}"
echo "BASE_URL=$BASE_URL"

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token="${4:-}"

  if [[ -n "$body" ]]; then
    curl -s -X "$method" "$BASE_URL$path" \
      ${token:+-H "X-Api-Key: $token"} \
      -H "Content-Type: application/json" \
      -d "$body"
  else
    curl -s -X "$method" "$BASE_URL$path" \
      ${token:+-H "X-Api-Key: $token"}
  fi
}

assert_no_error() {
  local json="$1"
  local label="$2"

  local err
  err="$(echo "$json" | jq -r '.error // empty')"

  if [[ -n "$err" ]]; then
    echo "[KO] $label"
    echo "$json" | jq
    exit 1
  fi

  echo "[OK] $label"
}

assert_non_empty() {
  local value="$1"
  local label="$2"

  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "[KO] $label"
    exit 1
  fi

  echo "[OK] $label"
}

assert_event_pending_or_sent_or_retrying() {
  local status="$1"
  local label="$2"

  case "$status" in
    pending|sent|retrying|failed)
      echo "[OK] $label status=$status"
      ;;
    *)
      echo "[KO] $label unexpected status=$status"
      exit 1
      ;;
  esac
}

echo
echo "1) Login admin"
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  TOKEN="$ADMIN_API_KEY"
  ME="$(api GET "/api/v2/me" "" "$TOKEN")"
  USER_ID="$(echo "$ME" | jq -r '.id // empty')"
  assert_non_empty "$USER_ID" "admin user id received"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
  echo "$LOGIN" | jq
  assert_no_error "$LOGIN" "admin login"
  TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
  USER_ID="$(echo "$LOGIN" | jq -r '.user.id // empty')"
  assert_non_empty "$TOKEN" "admin token received"
  assert_non_empty "$USER_ID" "admin user id received"
fi

echo
echo "2) Create notification config"
CONFIG="$(api POST "/api/v2/notifications/configs" "{
  \"name\":\"Business Notifications Test\",
  \"channel\":\"email\",
  \"is_enabled\":true,
  \"is_default\":false,
  \"config\":{
    \"to_email\":\"$ADMIN_EMAIL\"
  }
}" "$TOKEN")"
echo "$CONFIG" | jq
assert_no_error "$CONFIG" "notification config created"

CONFIG_ID="$(echo "$CONFIG" | jq -r '.id // empty')"
assert_non_empty "$CONFIG_ID" "notification config id"

EVENT_TYPES='[
  "job.created",
  "job.started",
  "job.ready",
  "job.links_ready",
  "job.completed",
  "job.failed",
  "job.cancelled",
  "provider.failed",
  "destination.sent",
  "destination.failed",
  "destination.cancelled"
]'

echo
echo "3) Create notification rule for business events"
RULE="$(api POST "/api/v2/notifications/rules" "{
  \"name\":\"Business Notifications Rule\",
  \"config_id\":\"$CONFIG_ID\",
  \"is_enabled\":true,
  \"scope\":\"user\",
  \"severity_min\":\"info\",
  \"event_types\":$EVENT_TYPES,
  \"rate_limit_per_hour\":100
}" "$TOKEN")"
echo "$RULE" | jq
assert_no_error "$RULE" "notification rule created"

RULE_ID="$(echo "$RULE" | jq -r '.id // empty')"
assert_non_empty "$RULE_ID" "notification rule id"

cleanup() {
  set +e
  if [[ -n "${RULE_ID:-}" && "$RULE_ID" != "null" ]]; then
    api DELETE "/api/v2/notifications/rules/$RULE_ID" "" "$TOKEN" >/dev/null
  fi
  if [[ -n "${CONFIG_ID:-}" && "$CONFIG_ID" != "null" ]]; then
    api DELETE "/api/v2/notifications/configs/$CONFIG_ID" "" "$TOKEN" >/dev/null
  fi
}
trap cleanup EXIT

echo
echo "3b) Ensure default provider config exists"
PROVIDER_CONFIG="$(api POST "/api/v2/providers" "{
  \"provider_name\":\"realdebrid\",
  \"api_key\":\"fake-business-notifications-test-key\",
  \"is_enabled\":true,
  \"is_default\":true
}" "$TOKEN")"
echo "$PROVIDER_CONFIG" | jq
assert_no_error "$PROVIDER_CONFIG" "default provider config available"

echo
echo "4) Create job through API to validate real job.created emission"
JOB_CREATE="$(api POST "/api/v2/jobs" "{
  \"source_type\":\"direct_link\",
  \"source_value\":\"https://example.com/link2nas-business-notification-test.bin\",
  \"auto_start\":false,
  \"send_to_destination\":false
}" "$TOKEN")"
echo "$JOB_CREATE" | jq
assert_no_error "$JOB_CREATE" "job created through API"

JOB_ID="$(echo "$JOB_CREATE" | jq -r '.id // .job.id // empty')"
assert_non_empty "$JOB_ID" "job id"

sleep 0.2

echo
echo "5) Verify job.created notification event"
EVENTS_CREATED="$(api GET "/api/v2/admin/notifications/events?limit=100" "" "$TOKEN")"
JOB_CREATED_EVENT="$(echo "$EVENTS_CREATED" | jq --arg job "$JOB_ID" --arg rule "$RULE_ID" --arg config "$CONFIG_ID" '
  [.[] | select(.job_id==$job and .type=="job.created") | select((.triggered_by_rule_ids // []) | index($rule)) | select((.triggered_by_config_ids // []) | index($config))][0] // {}
')"

echo "$JOB_CREATED_EVENT" | jq

JOB_CREATED_ID="$(echo "$JOB_CREATED_EVENT" | jq -r '.id // empty')"
JOB_CREATED_STATUS="$(echo "$JOB_CREATED_EVENT" | jq -r '.status // empty')"

assert_non_empty "$JOB_CREATED_ID" "job.created event matched rule/config"
assert_event_pending_or_sent_or_retrying "$JOB_CREATED_STATUS" "job.created event"

echo
echo "6) Emit remaining business events through JobService"
EMIT_RESULT="$(python3 - <<PY
import json
from app import app

job_id = "$JOB_ID"
user_id = "$USER_ID"

events = [
    ("job.started", "info", "Job started", "Job has started."),
    ("job.ready", "info", "Job ready", "Job direct links are ready."),
    ("job.links_ready", "info", "Links ready", "Direct links are available for this job."),
    ("destination.sent", "info", "Destination sent", "Job was sent to destination."),
    ("job.completed", "info", "Job completed", "Job completed successfully."),
    ("provider.failed", "error", "Provider failed", "Fake provider failure."),
    ("destination.failed", "error", "Destination failed", "Fake destination failure."),
    ("job.failed", "error", "Job failed", "Fake job failure."),
    ("destination.cancelled", "warning", "Destination cancelled", "Destination cancellation requested."),
    ("job.cancelled", "warning", "Job cancelled", "Job was cancelled."),
]

with app.app_context():
    repo = app.config["JOB_REPOSITORY_V2"]
    service = app.config["JOB_SERVICE_V2"]

    job = None

    # Repository signatures are not fully standardized across iterations.
    for args in (
        (user_id, job_id),
        (job_id,),
    ):
        try:
            job = repo.get_by_id(*args)
            if job:
                break
        except TypeError:
            pass

    if not job:
        raise RuntimeError(f"Job not found: {job_id}")

    created = []

    for event_type, severity, title, message in events:
        service._emit_notification_event(
            job,
            event_type=event_type,
            severity=severity,
            title=title,
            message=message,
            payload={
                "test": True,
                "business_notifications_test": True,
            },
        )
        created.append(event_type)

    print(json.dumps({"ok": True, "created": created}, ensure_ascii=False))
PY
)"
echo "$EMIT_RESULT" | jq
assert_no_error "$EMIT_RESULT" "business events emitted"

echo
echo "7) Verify all business events exist and matched rule/config"
EVENTS_AFTER="$(api GET "/api/v2/admin/notifications/events?limit=200" "" "$TOKEN")"

MISSING="$(echo "$EVENTS_AFTER" | jq -r --arg job "$JOB_ID" --arg rule "$RULE_ID" --arg config "$CONFIG_ID" '
  . as $events
  |
  [
    "job.created",
    "job.started",
    "job.ready",
    "job.links_ready",
    "job.completed",
    "job.failed",
    "job.cancelled",
    "provider.failed",
    "destination.sent",
    "destination.failed",
    "destination.cancelled"
  ] as $expected
  |
  $expected[]
  |
  . as $type
  |
  (
    [$events[] | select(.job_id==$job and .type==$type) | select((.triggered_by_rule_ids // []) | index($rule)) | select((.triggered_by_config_ids // []) | index($config))]
    | length
  ) as $count
  |
  select($count < 1)
')"

if [[ -n "$MISSING" ]]; then
  echo "[KO] missing business notification events:"
  echo "$MISSING"
  echo "$EVENTS_AFTER" | jq --arg job "$JOB_ID" '.[] | select(.job_id==$job) | {id,type,status,severity,triggered_by_rule_ids,triggered_by_config_ids,title}'
  exit 1
fi

echo "[OK] all business events exist and matched rule/config"

echo
echo "8) Display business events summary"
echo "$EVENTS_AFTER" | jq --arg job "$JOB_ID" '
  [.[] | select(.job_id==$job) | {
    id,
    type,
    severity,
    status,
    attempts,
    title,
    triggered_by_rule_ids,
    triggered_by_config_ids,
    created_at
  }]
'

echo
echo "9) Run dispatcher once"
DISPATCH="$(api POST "/api/v2/admin/notifications/dispatcher/run-once" "{
  \"user_id\":\"$USER_ID\",
  \"limit\":50
}" "$TOKEN")"
echo "$DISPATCH" | jq
assert_no_error "$DISPATCH" "dispatcher run executed"

PROCESSED="$(echo "$DISPATCH" | jq -r '.processed // 0')"
if [[ "$PROCESSED" -lt 1 ]]; then
  echo "[KO] dispatcher processed no event"
  exit 1
fi
echo "[OK] dispatcher processed events: $PROCESSED"

echo
echo "10) Verify business events dispatcher statuses"
EVENTS_DISPATCHED="$(api GET "/api/v2/admin/notifications/events?limit=200" "" "$TOKEN")"

BAD_STATUS="$(echo "$EVENTS_DISPATCHED" | jq -r --arg job "$JOB_ID" '
  [.[] | select(.job_id==$job)]
  | .[]
  | select(.status as $s | ["sent","retrying","failed","ignored","pending"] | index($s) | not)
  | "\(.type)=\(.status)"
')"

if [[ -n "$BAD_STATUS" ]]; then
  echo "[KO] unexpected dispatcher statuses:"
  echo "$BAD_STATUS"
  exit 1
fi

echo "$EVENTS_DISPATCHED" | jq --arg job "$JOB_ID" '
  [.[] | select(.job_id==$job) | {
    type,
    status,
    attempts,
    last_error,
    sent_at
  }]
'

echo "[OK] dispatcher statuses valid"

echo
echo "11) Cleanup notification rule/config"
cleanup
trap - EXIT

echo "[OK] notification rule/config cleaned"

echo
echo "=== OK: business notifications workflow passed ==="
