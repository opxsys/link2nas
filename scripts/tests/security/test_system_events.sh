#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 system events test ==="
echo "Backend=${V2_DATABASE_BACKEND:-sqlite}"
echo "BASE_URL=$BASE_URL"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[KO] Missing command: $1"
    exit 1
  }
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

assert_no_error() {
  local json="$1"
  local label="$2"
  local error
  error="$(echo "$json" | jq -r 'if type == "object" then (.error // empty) else empty end')"

  if [[ -n "$error" ]]; then
    echo "[KO] $label: $error"
    echo "$json" | jq
    exit 1
  fi

  echo "[OK] $label"
}

assert_equals() {
  local actual="$1"
  local expected="$2"
  local label="$3"

  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label"
    echo "     expected: $expected"
    echo "     actual:   $actual"
    exit 1
  fi

  echo "[OK] $label"
}

assert_ge() {
  local actual="$1"
  local expected="$2"
  local label="$3"

  if (( actual < expected )); then
    echo "[KO] $label"
    echo "     expected >= $expected"
    echo "     actual:     $actual"
    exit 1
  fi

  echo "[OK] $label"
}

need_cmd curl
need_cmd jq
need_cmd python3

echo
echo "0) Ensure first admin exists"
SETUP_STATUS="$(api GET "/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
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
echo "1) Login admin"
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
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "[KO] token missing"
    exit 1
  fi
fi

echo
echo "2) Read system-events settings"
SETTINGS="$(api GET "/api/v2/admin/app-settings/system-events" "" "$TOKEN")"
echo "$SETTINGS" | jq
assert_no_error "$SETTINGS" "system-events settings read"

DEDUP_ENABLED="$(echo "$SETTINGS" | jq -r '.dedup.enabled')"
DEDUP_MINUTES="$(echo "$SETTINGS" | jq -r '.dedup.dedup_minutes')"

if [[ "$DEDUP_ENABLED" == "null" || "$DEDUP_MINUTES" == "null" ]]; then
  echo "[KO] invalid system-events settings shape"
  exit 1
fi

echo "[OK] dedup settings shape"

echo
echo "3) Save deterministic dedup settings"
SAVE_SETTINGS="$(api PUT "/api/v2/admin/app-settings/system-events" "{
  \"dedup\": {
    \"enabled\": true,
    \"dedup_minutes\": 60
  }
}" "$TOKEN")"
echo "$SAVE_SETTINGS" | jq
assert_no_error "$SAVE_SETTINGS" "system-events settings saved"
assert_equals "$(echo "$SAVE_SETTINGS" | jq -r '.dedup.enabled')" "true" "dedup enabled"
assert_equals "$(echo "$SAVE_SETTINGS" | jq -r '.dedup.dedup_minutes')" "60" "dedup minutes"

echo
echo "4) Direct SystemEventService smoke + dedup"
PY_RESULT="$(python3 - <<'PY'
import json
import uuid
from app import app

fingerprint = f"test.system_events.direct.{uuid.uuid4()}"

with app.app_context():
    service = app.config["SYSTEM_EVENT_SERVICE_V2"]

    first = service.create_for_super_admins(
        event_type="system.cleanup.failed",
        severity="warning",
        title="System events direct test",
        message="Direct system event smoke test",
        component="cleanup",
        fingerprint=fingerprint,
        details={"test": True},
    )

    second = service.create_for_super_admins(
        event_type="system.cleanup.failed",
        severity="warning",
        title="System events direct test duplicate",
        message="Direct system event smoke test duplicate",
        component="cleanup",
        fingerprint=fingerprint,
        details={"test": True, "duplicate": True},
    )

print(json.dumps({
    "first": first,
    "second": second,
}, ensure_ascii=False))
PY
)"
echo "$PY_RESULT" | jq

FIRST_CREATED="$(echo "$PY_RESULT" | jq -r '.first.created')"
SECOND_SKIPPED="$(echo "$PY_RESULT" | jq -r '.second.skipped')"

assert_ge "$FIRST_CREATED" 1 "first direct system event created"
assert_ge "$SECOND_SKIPPED" 1 "second direct system event deduplicated"
echo
echo "4b) System scope rule matching"

CONFIG="$(api POST "/api/v2/notifications/configs" "{
  \"name\":\"System Events Scope Test\",
  \"channel\":\"email\",
  \"is_enabled\":true,
  \"is_default\":false,
  \"config\":{
    \"to_email\":\"admin@test.local\"
  }
}" "$TOKEN")"
echo "$CONFIG" | jq
assert_no_error "$CONFIG" "system scope config created"

CONFIG_ID="$(echo "$CONFIG" | jq -r '.id // empty')"
if [[ -z "$CONFIG_ID" || "$CONFIG_ID" == "null" ]]; then
  echo "[KO] config id missing"
  exit 1
fi

RULE="$(api POST "/api/v2/notifications/rules" "{
  \"name\":\"System Events Scope Rule\",
  \"config_id\":\"$CONFIG_ID\",
  \"is_enabled\":true,
  \"scope\":\"system\",
  \"severity_min\":\"warning\",
  \"event_types\":[\"system.scheduler.failed\"],
  \"rate_limit_per_hour\":30
}" "$TOKEN")"
echo "$RULE" | jq
assert_no_error "$RULE" "system scope rule created"

RULE_ID="$(echo "$RULE" | jq -r '.id // empty')"
if [[ -z "$RULE_ID" || "$RULE_ID" == "null" ]]; then
  echo "[KO] rule id missing"
  exit 1
fi

MATCH_RESULT="$(python3 - <<'PY'
import json
import uuid
from app import app

with app.app_context():
    svc = app.config["SYSTEM_EVENT_SERVICE_V2"]

    result = svc.create_for_super_admins(
        event_type="system.scheduler.failed",
        severity="error",
        title="System scope matching test",
        message="This system event should match a system notification rule.",
        component="scheduler",
        fingerprint=f"test.system_scope.{uuid.uuid4()}",
        details={"test": True},
    )

print(json.dumps(result, ensure_ascii=False))
PY
)"
echo "$MATCH_RESULT" | jq

MATCH_EVENTS="$(api GET "/api/v2/admin/notifications/events?limit=50" "" "$TOKEN")"
MATCHED_COUNT="$(echo "$MATCH_EVENTS" | jq --arg rid "$RULE_ID" --arg cid "$CONFIG_ID" '
  [
    .[]
    | select(.title == "System scope matching test")
    | select(.status == "pending")
    | select(.triggered_by_rule_ids | index($rid))
    | select(.triggered_by_config_ids | index($cid))
  ]
  | length
')"

assert_ge "$MATCHED_COUNT" 1 "system scope rule matched event"

DELETE_RULE="$(api DELETE "/api/v2/notifications/rules/$RULE_ID" "" "$TOKEN")"
echo "$DELETE_RULE" | jq
assert_no_error "$DELETE_RULE" "system scope rule deleted"

DELETE_CONFIG="$(api DELETE "/api/v2/notifications/configs/$CONFIG_ID" "" "$TOKEN")"
echo "$DELETE_CONFIG" | jq
assert_no_error "$DELETE_CONFIG" "system scope config deleted"
echo
echo "4c) System scoped event dispatcher processing"

CONFIG="$(api POST "/api/v2/notifications/configs" "{
  \"name\":\"System Dispatcher Scope Test\",
  \"channel\":\"email\",
  \"is_enabled\":true,
  \"is_default\":false,
  \"config\":{
    \"to_email\":\"admin@test.local\"
  }
}" "$TOKEN")"
echo "$CONFIG" | jq
assert_no_error "$CONFIG" "system dispatcher config created"

CONFIG_ID="$(echo "$CONFIG" | jq -r '.id // empty')"
if [[ -z "$CONFIG_ID" || "$CONFIG_ID" == "null" ]]; then
  echo "[KO] dispatcher config id missing"
  exit 1
fi

RULE="$(api POST "/api/v2/notifications/rules" "{
  \"name\":\"System Dispatcher Scope Rule\",
  \"config_id\":\"$CONFIG_ID\",
  \"is_enabled\":true,
  \"scope\":\"system\",
  \"severity_min\":\"warning\",
  \"event_types\":[\"system.smtp.failed\"],
  \"rate_limit_per_hour\":30
}" "$TOKEN")"
echo "$RULE" | jq
assert_no_error "$RULE" "system dispatcher rule created"

RULE_ID="$(echo "$RULE" | jq -r '.id // empty')"
if [[ -z "$RULE_ID" || "$RULE_ID" == "null" ]]; then
  echo "[KO] dispatcher rule id missing"
  exit 1
fi

DISPATCH_EVENT_RESULT="$(python3 - <<'PY'
import json
import uuid
from app import app

with app.app_context():
    svc = app.config["SYSTEM_EVENT_SERVICE_V2"]

    result = svc.create_for_super_admins(
        event_type="system.smtp.failed",
        severity="error",
        title="System dispatcher processing test",
        message="This system event should be processed by dispatcher.",
        component="smtp",
        fingerprint=f"test.system_dispatcher.{uuid.uuid4()}",
        details={"test": True},
    )

print(json.dumps(result, ensure_ascii=False))
PY
)"
echo "$DISPATCH_EVENT_RESULT" | jq

EVENTS_BEFORE="$(api GET "/api/v2/admin/notifications/events?limit=80" "" "$TOKEN")"
EVENT_ID="$(echo "$EVENTS_BEFORE" | jq -r --arg rid "$RULE_ID" --arg cid "$CONFIG_ID" '
  [
    .[]
    | select(.title == "System dispatcher processing test")
    | select(.status == "pending")
    | select(.triggered_by_rule_ids | index($rid))
    | select(.triggered_by_config_ids | index($cid))
  ][0].id // empty
')"

if [[ -z "$EVENT_ID" || "$EVENT_ID" == "null" ]]; then
  echo "[KO] pending system dispatcher event not found"
  echo "$EVENTS_BEFORE" | jq '.[] | select(.title == "System dispatcher processing test")'
  exit 1
fi

echo "[OK] pending system dispatcher event found"

DISPATCH_RESULT="$(api POST "/api/v2/admin/notifications/dispatcher/run-once" "{
  \"limit\": 25
}" "$TOKEN")"
echo "$DISPATCH_RESULT" | jq
assert_no_error "$DISPATCH_RESULT" "dispatcher run executed"

EVENTS_AFTER="$(api GET "/api/v2/admin/notifications/events?limit=80" "" "$TOKEN")"

FINAL_EVENT="$(echo "$EVENTS_AFTER" | jq --arg id "$EVENT_ID" '.[] | select(.id == $id)')"
echo "$FINAL_EVENT" | jq

FINAL_STATUS="$(echo "$FINAL_EVENT" | jq -r '.status // empty')"
FINAL_ATTEMPTS="$(echo "$FINAL_EVENT" | jq -r '.attempts // 0')"
FINAL_RULE_MATCH="$(echo "$FINAL_EVENT" | jq -r --arg rid "$RULE_ID" '.triggered_by_rule_ids | index($rid) != null')"
FINAL_CONFIG_MATCH="$(echo "$FINAL_EVENT" | jq -r --arg cid "$CONFIG_ID" '.triggered_by_config_ids | index($cid) != null')"

if [[ "$FINAL_STATUS" != "sent" && "$FINAL_STATUS" != "retrying" ]]; then
  echo "[KO] expected system dispatcher event status sent or retrying, got: $FINAL_STATUS"
  exit 1
fi

echo "[OK] system dispatcher event processed with status=$FINAL_STATUS"

assert_equals "$FINAL_RULE_MATCH" "true" "dispatcher event kept matching rule id"
assert_equals "$FINAL_CONFIG_MATCH" "true" "dispatcher event kept matching config id"

if [[ "$FINAL_STATUS" == "retrying" ]]; then
  assert_ge "$FINAL_ATTEMPTS" 1 "retrying event attempts incremented"
fi

DELETE_RULE="$(api DELETE "/api/v2/notifications/rules/$RULE_ID" "" "$TOKEN")"
echo "$DELETE_RULE" | jq
assert_no_error "$DELETE_RULE" "system dispatcher rule deleted"

DELETE_CONFIG="$(api DELETE "/api/v2/notifications/configs/$CONFIG_ID" "" "$TOKEN")"
echo "$DELETE_CONFIG" | jq
assert_no_error "$DELETE_CONFIG" "system dispatcher config deleted"

echo
echo "5) Emit maintenance/storage/smtp/dispatcher/scheduler smoke events"
PY_EVENTS="$(python3 - <<'PY'
import json
import uuid
from app import app
from backend.routes_v2.admin_maintenance import _emit_maintenance_system_events
from backend.services_v2.scheduler_loop import _emit_scheduler_failed, _emit_system_event

with app.app_context():
    # storage low
    _emit_maintenance_system_events({
        "ok": True,
        "generated_at": "2026-05-12T00:00:00+00:00",
        "database": {"ok": True, "backend": "test", "message": "OK"},
        "paths": [],
        "disk": {
            "ok": True,
            "path": "/fake",
            "total_bytes": 1000,
            "used_bytes": 960,
            "free_bytes": 40,
            "percent_used": 96,
            "percent_free": 4,
            "message": "Fake low disk",
        },
    })

    # maintenance failed
    _emit_maintenance_system_events({
        "ok": False,
        "generated_at": "2026-05-12T00:00:00+00:00",
        "database": {"ok": False, "backend": "test", "message": "Fake DB failure"},
        "paths": [
            {
                "name": "tmp",
                "path": "/fake/tmp",
                "required": True,
                "exists": True,
                "is_dir": True,
                "writable": False,
                "ok": False,
                "message": "Fake write failure",
            }
        ],
        "disk": {
            "ok": True,
            "path": "/fake",
            "total_bytes": 1000,
            "used_bytes": 500,
            "free_bytes": 500,
            "percent_used": 50,
            "percent_free": 50,
            "message": "Fake disk OK",
        },
    })

    service = app.config["SYSTEM_EVENT_SERVICE_V2"]

    smtp = service.create_for_super_admins(
        event_type="system.smtp.failed",
        severity="error",
        title="SMTP test failed",
        message="SMTP test failed: fake system event test",
        component="smtp",
        fingerprint=f"test.system_events.smtp.{uuid.uuid4()}",
        details={"error": "fake smtp error"},
    )

    dispatcher = service.create_for_super_admins(
        event_type="system.notification_dispatcher.failed",
        severity="warning",
        title="Notification dispatcher completed with errors",
        message="Notification dispatcher completed with 1 error(s).",
        component="notification_dispatcher",
        fingerprint=f"test.system_events.dispatcher.{uuid.uuid4()}",
        details={"errors": [{"error": "fake dispatcher error"}]},
    )

    _emit_scheduler_failed(
        app,
        error="fake scheduler error",
        details={"phase": "test_system_events"},
    )

print(json.dumps({
    "smtp": smtp,
    "dispatcher": dispatcher,
    "ok": True,
}, ensure_ascii=False))
PY
)"
echo "$PY_EVENTS" | jq
assert_equals "$(echo "$PY_EVENTS" | jq -r '.ok')" "true" "system event smoke emitters ran"

echo
echo "6) Verify event types exist"
EVENTS="$(api GET "/api/v2/admin/notifications/events?limit=200" "" "$TOKEN")"
echo "$EVENTS" | jq 'map({type,severity,status,title,created_at}) | .[0:20]'
assert_no_error "$EVENTS" "admin events listed"

for event_type in \
  "system.cleanup.failed" \
  "system.maintenance.failed" \
  "system.smtp.failed" \
  "system.notification_dispatcher.failed" \
  "system.scheduler.failed" \
  "system.storage.low"
do
  COUNT="$(echo "$EVENTS" | jq --arg t "$event_type" '[.[] | select(.type == $t)] | length')"
  assert_ge "$COUNT" 1 "$event_type exists"
done

echo
echo "7) Restore original system-events settings"
RESTORE="$(api PUT "/api/v2/admin/app-settings/system-events" "{
  \"dedup\": {
    \"enabled\": $DEDUP_ENABLED,
    \"dedup_minutes\": $DEDUP_MINUTES
  }
}" "$TOKEN")"
echo "$RESTORE" | jq
assert_no_error "$RESTORE" "system-events settings restored"

echo
echo "=== OK: system events workflow passed ==="
