#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 notifications full test ==="
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
    echo "[KO] $label: expected '$expected', got '$actual'"
    exit 1
  fi

  echo "[OK] $label"
}

need_cmd curl
need_cmd jq

echo
echo "0) Ensure first admin exists"

SETUP_STATUS="$(api GET "/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq

SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo "[INFO] Creating first admin before repository tests"

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
echo "1) Repository + service direct tests"

python3 - <<'PY'
import json
import uuid
from dataclasses import fields
from datetime import UTC, datetime, timedelta

from config import Settings
from backend.models.user import User
from backend.models.notification_config import NotificationConfig
from backend.models.notification_event import NotificationEvent
from backend.models.notification_rule import NotificationRule
from backend.repositories.factory import build_repositories
from backend.services_v2.crypto_service import CryptoService
from backend.services_v2.notification_service import (
    NotificationNotFoundError,
    NotificationService,
    NotificationValidationError,
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def make_user(**overrides):
    timestamp = now()

    values = {
        "id": str(uuid.uuid4()),
        "email": f"notif-full-{uuid.uuid4().hex[:8]}@test.local",
        "password_hash": "test",
        "display_name": "Notification Full Test User",
        "role": "user",
        "is_active": True,
        "is_super_admin": False,
        "created_at": timestamp,
        "updated_at": timestamp,
        "last_login_at": None,
        "valid_from": None,
        "account_expires_at": None,
        "email_verified": False,
        "email_verified_at": None,
        "force_password_change": False,
    }

    values.update(overrides)

    allowed = {field.name for field in fields(User)}
    filtered = {key: value for key, value in values.items() if key in allowed}

    return User(**filtered)


settings = Settings()
settings.ensure_directories()

repos = build_repositories(settings)
crypto = CryptoService(settings.V2_SECRET_ENCRYPTION_KEY)

service = NotificationService(
    notification_config_repository=repos.notification_config_repository,
    notification_rule_repository=repos.notification_rule_repository,
    notification_event_repository=repos.notification_event_repository,
    crypto_service=crypto,
)

timestamp = now()
user = make_user()
repos.user_repository.create(user)
user_id = user.id

# ---------------------------------------------------------------------
# Repository level
# ---------------------------------------------------------------------

config_id = str(uuid.uuid4())

config = NotificationConfig(
    id=config_id,
    user_id=user_id,
    name="Repo Gotify",
    channel="gotify",
    is_enabled=True,
    is_default=True,
    config_json=json.dumps({
        "server_url": "https://gotify.example.com",
        "token": "repo-secret",
    }),
    created_at=timestamp,
    updated_at=timestamp,
)

repos.notification_config_repository.create(config)

loaded_config = repos.notification_config_repository.get_by_id(user_id, config_id)
assert loaded_config is not None, "notification config not found"
assert loaded_config.name == "Repo Gotify"
assert loaded_config.channel == "gotify"
assert loaded_config.is_enabled is True
assert loaded_config.is_default is True

default_config = repos.notification_config_repository.get_default_for_channel(user_id, "gotify")
assert default_config is not None
assert default_config.id == config_id

rule_id = str(uuid.uuid4())

rule = NotificationRule(
    id=rule_id,
    user_id=user_id,
    name="Repo failures rule",
    scope="user",
    is_enabled=True,
    config_id=config_id,
    severity_min="warning",
    event_types_json=json.dumps(["job.failed", "destination.failed"]),
    rate_limit_per_hour=12,
    created_at=timestamp,
    updated_at=timestamp,
)

repos.notification_rule_repository.create(rule)

loaded_rule = repos.notification_rule_repository.get_by_id(user_id, rule_id)
assert loaded_rule is not None, "notification rule not found"
assert loaded_rule.name == "Repo failures rule"
assert loaded_rule.config_id == config_id
assert loaded_rule.severity_min == "warning"

enabled_rules = repos.notification_rule_repository.list_enabled_for_user(user_id, scope="user")
assert any(item.id == rule_id for item in enabled_rules), "enabled rule should be listed"

event_id = str(uuid.uuid4())

event = NotificationEvent(
    id=event_id,
    user_id=user_id,
    job_id="job-repo-123",
    type="job.failed",
    severity="error",
    title="Repo job failed",
    message="The repo job failed",
    payload_json=json.dumps({"job_id": "job-repo-123"}),
    status="pending",
    attempts=0,
    max_attempts=5,
    last_error=None,
    triggered_by_rule_ids_json=json.dumps([rule_id]),
    triggered_by_config_ids_json=json.dumps([config_id]),
    next_retry_at=None,
    created_at=timestamp,
    updated_at=timestamp,
    sent_at=None,
)

repos.notification_event_repository.create(event)

loaded_event = repos.notification_event_repository.get_by_id(user_id, event_id)
assert loaded_event is not None, "notification event not found"
assert loaded_event.type == "job.failed"
assert loaded_event.status == "pending"
assert rule_id in json.loads(loaded_event.triggered_by_rule_ids_json)
assert config_id in json.loads(loaded_event.triggered_by_config_ids_json)

due_events = repos.notification_event_repository.list_pending_due(now(), limit=10)
assert any(e.id == event_id for e in due_events), "pending event should be due"

repos.notification_event_repository.increment_attempt(
    event_id,
    "temporary error",
    now(),
    (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
)

retry_event = repos.notification_event_repository.get_by_id(user_id, event_id)
assert retry_event is not None
assert retry_event.status == "retrying"
assert retry_event.attempts == 1
assert retry_event.last_error == "temporary error"
assert retry_event.next_retry_at is not None

sent_at = now()
repos.notification_event_repository.mark_sent(event_id, sent_at)

sent_event = repos.notification_event_repository.get_by_id(user_id, event_id)
assert sent_event is not None
assert sent_event.status == "sent"
assert sent_event.sent_at == sent_at
assert sent_event.last_error is None

# ---------------------------------------------------------------------
# Service level
# ---------------------------------------------------------------------

created_endpoint = service.create_config(
    user_id,
    {
        "name": "Service Gotify default",
        "channel": "gotify",
        "is_enabled": True,
        "is_default": True,
        "config": {
            "server_url": "https://gotify-service.example.com/",
            "token": "service-secret-token",
        },
    },
)

assert created_endpoint["name"] == "Service Gotify default"
assert created_endpoint["channel"] == "gotify"
assert created_endpoint["is_enabled"] is True
assert created_endpoint["is_default"] is True
assert created_endpoint["config"]["server_url"] == "https://gotify-service.example.com"
assert created_endpoint["config"]["has_token"] is True
assert "token" not in created_endpoint["config"]

service_config_id = created_endpoint["id"]

raw_service_config = repos.notification_config_repository.get_by_id(user_id, service_config_id)

assert raw_service_config is not None


assert "service-secret-token" not in raw_service_config.config_json, "config_json should be encrypted"

updated_endpoint = service.update_config(
    user_id,
    service_config_id,
    {
        "name": "Service Gotify updated",
        "channel": "gotify",
        "is_enabled": True,
        "is_default": True,
        "config": {
            "server_url": "https://gotify-service2.example.com",
        },
    },
)

assert updated_endpoint["name"] == "Service Gotify updated"
assert updated_endpoint["config"]["server_url"] == "https://gotify-service2.example.com"
assert updated_endpoint["config"]["has_token"] is True
assert "token" not in updated_endpoint["config"]

created_rule = service.create_rule(
    user_id,
    {
        "name": "Service failures rule",
        "scope": "user",
        "is_enabled": True,
        "config_id": service_config_id,
        "severity_min": "error",
        "event_types": ["job.failed", "destination.failed"],
        "rate_limit_per_hour": 5,
    },
)

assert created_rule["name"] == "Service failures rule"
assert created_rule["config_id"] == service_config_id
assert created_rule["severity_min"] == "error"
assert created_rule["event_types"] == ["job.failed", "destination.failed"]
assert created_rule["rate_limit_per_hour"] == 5

service_rule_id = created_rule["id"]

ignored_event = service.create_event(
    user_id=user_id,
    type="provider.failed",
    severity="warning",
    title="Warning provider failed",
    message="Warning should not match configured job/destination rules",
    job_id="job-warning-123",
    payload={"job_id": "job-warning-123"},
)

assert ignored_event["status"] == "ignored", ignored_event
assert service_rule_id not in ignored_event["triggered_by_rule_ids"], ignored_event

matched_event = service.create_event(
    user_id=user_id,
    type="job.failed",
    severity="error",
    title="Error job failed",
    message="Error should match",
    job_id="job-error-123",
    payload={"job_id": "job-error-123"},
)

assert matched_event["status"] == "pending", matched_event
assert service_rule_id in matched_event["triggered_by_rule_ids"], matched_event
assert service_config_id in matched_event["triggered_by_config_ids"], matched_event

events = service.list_events(user_id)
assert any(item["id"] == matched_event["id"] for item in events)

try:
    service.create_config(
        user_id,
        {
            "name": "Bad channel",
            "channel": "sms",
            "config": {},
        },
    )
    raise AssertionError("invalid channel should fail")
except NotificationValidationError:
    pass

try:
    service.get_config(user_id, str(uuid.uuid4()))
    raise AssertionError("missing config should fail")
except NotificationNotFoundError:
    pass

deleted_rule = service.delete_rule(user_id, service_rule_id)
assert deleted_rule is True

deleted_config = service.delete_config(user_id, service_config_id)
assert deleted_config is True

print("[OK] repository and service workflow passed")
PY

echo
echo "2) API workflow"

echo
echo "2.1) Setup status"
SETUP_STATUS="$(api GET "/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo
  echo "2.2) Create first admin"
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
echo "2.3) Login"
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
  assert_no_error "$LOGIN" "login"
  TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "[KO] token missing"
    exit 1
  fi
  echo "[OK] token received"
fi

echo
echo "2.4) List configs"
LIST_CONFIGS_BEFORE="$(api GET "/api/v2/notifications/configs" "" "$TOKEN")"
echo "$LIST_CONFIGS_BEFORE" | jq
assert_no_error "$LIST_CONFIGS_BEFORE" "configs listed"

echo
echo "2.5) Create Gotify endpoint"
CREATE_CONFIG="$(api POST "/api/v2/notifications/configs" "{
  \"name\": \"Gotify API Endpoint\",
  \"channel\": \"gotify\",
  \"is_enabled\": true,
  \"is_default\": true,
  \"config\": {
    \"server_url\": \"https://gotify.example.com/\",
    \"token\": \"super-secret-token\"
  }
}" "$TOKEN")"
echo "$CREATE_CONFIG" | jq
assert_no_error "$CREATE_CONFIG" "gotify endpoint created"

CONFIG_ID="$(echo "$CREATE_CONFIG" | jq -r '.id // empty')"
if [[ -z "$CONFIG_ID" || "$CONFIG_ID" == "null" ]]; then
  echo "[KO] config id missing"
  exit 1
fi

assert_equals "$(echo "$CREATE_CONFIG" | jq -r '.channel')" "gotify" "created endpoint channel"
assert_equals "$(echo "$CREATE_CONFIG" | jq -r '.is_default')" "true" "created endpoint default"
assert_equals "$(echo "$CREATE_CONFIG" | jq -r '.config.has_token')" "true" "gotify token hidden as has_token"

TOKEN_LEAK="$(echo "$CREATE_CONFIG" | jq -r '.config.token // empty')"
if [[ -n "$TOKEN_LEAK" ]]; then
  echo "[KO] gotify token leaked in API response"
  exit 1
fi
echo "[OK] gotify token not leaked"

echo
echo "2.6) Update Gotify endpoint without resending token"
UPDATE_CONFIG="$(api PUT "/api/v2/notifications/configs/$CONFIG_ID" "{
  \"name\": \"Gotify API Endpoint Updated\",
  \"channel\": \"gotify\",
  \"is_enabled\": true,
  \"is_default\": true,
  \"config\": {
    \"server_url\": \"https://gotify2.example.com\"
  }
}" "$TOKEN")"
echo "$UPDATE_CONFIG" | jq
assert_no_error "$UPDATE_CONFIG" "gotify endpoint updated without token"

assert_equals "$(echo "$UPDATE_CONFIG" | jq -r '.name')" "Gotify API Endpoint Updated" "updated endpoint name"
assert_equals "$(echo "$UPDATE_CONFIG" | jq -r '.config.server_url')" "https://gotify2.example.com" "updated endpoint server_url"
assert_equals "$(echo "$UPDATE_CONFIG" | jq -r '.config.has_token')" "true" "token preserved"

echo
echo "2.7) Create notification rule"
CREATE_RULE="$(api POST "/api/v2/notifications/rules" "{
  \"name\": \"API failures rule\",
  \"scope\": \"user\",
  \"is_enabled\": true,
  \"config_id\": \"$CONFIG_ID\",
  \"severity_min\": \"error\",
  \"event_types\": [\"job.failed\", \"destination.failed\"],
  \"rate_limit_per_hour\": 5
}" "$TOKEN")"
echo "$CREATE_RULE" | jq
assert_no_error "$CREATE_RULE" "notification rule created"

RULE_ID="$(echo "$CREATE_RULE" | jq -r '.id // empty')"
if [[ -z "$RULE_ID" || "$RULE_ID" == "null" ]]; then
  echo "[KO] rule id missing"
  exit 1
fi

assert_equals "$(echo "$CREATE_RULE" | jq -r '.config_id')" "$CONFIG_ID" "rule config_id"
assert_equals "$(echo "$CREATE_RULE" | jq -r '.severity_min')" "error" "rule severity"
assert_equals "$(echo "$CREATE_RULE" | jq -r '.rate_limit_per_hour')" "5" "rule rate limit"

echo
echo "2.8) Read rule"
READ_RULE="$(api GET "/api/v2/notifications/rules/$RULE_ID" "" "$TOKEN")"
echo "$READ_RULE" | jq
assert_no_error "$READ_RULE" "rule read"
assert_equals "$(echo "$READ_RULE" | jq -r '.id')" "$RULE_ID" "read rule id"

echo
echo "2.9) Update rule"
UPDATE_RULE="$(api PUT "/api/v2/notifications/rules/$RULE_ID" "{
  \"name\": \"API critical rule\",
  \"scope\": \"user\",
  \"is_enabled\": true,
  \"config_id\": \"$CONFIG_ID\",
  \"severity_min\": \"critical\",
  \"event_types\": [],
  \"rate_limit_per_hour\": 2
}" "$TOKEN")"
echo "$UPDATE_RULE" | jq
assert_no_error "$UPDATE_RULE" "rule updated"

assert_equals "$(echo "$UPDATE_RULE" | jq -r '.name')" "API critical rule" "updated rule name"
assert_equals "$(echo "$UPDATE_RULE" | jq -r '.severity_min')" "critical" "updated rule severity"
assert_equals "$(echo "$UPDATE_RULE" | jq -r '.rate_limit_per_hour')" "2" "updated rule rate limit"

echo
echo "2.10) Invalid channel must fail"
BAD_CONFIG="$(api POST "/api/v2/notifications/configs" "{
  \"name\": \"Bad\",
  \"channel\": \"sms\",
  \"config\": {}
}" "$TOKEN")"
echo "$BAD_CONFIG" | jq

BAD_CONFIG_ERROR="$(echo "$BAD_CONFIG" | jq -r '.error // empty')"
if [[ "$BAD_CONFIG_ERROR" != "Unsupported notification channel" ]]; then
  echo "[KO] expected unsupported channel error, got: $BAD_CONFIG_ERROR"
  exit 1
fi
echo "[OK] invalid channel rejected"

echo
echo "2.11) Invalid rule config_id must fail"
BAD_RULE="$(api POST "/api/v2/notifications/rules" "{
  \"name\": \"Bad rule\",
  \"scope\": \"user\",
  \"is_enabled\": true,
  \"config_id\": \"missing-config-id\",
  \"severity_min\": \"error\",
  \"event_types\": [],
  \"rate_limit_per_hour\": 1
}" "$TOKEN")"
echo "$BAD_RULE" | jq

BAD_RULE_ERROR="$(echo "$BAD_RULE" | jq -r '.error // empty')"
if [[ "$BAD_RULE_ERROR" != "Notification config not found" ]]; then
  echo "[KO] expected missing config error, got: $BAD_RULE_ERROR"
  exit 1
fi
echo "[OK] invalid rule config_id rejected"

echo
echo "2.12) List events"
EVENTS="$(api GET "/api/v2/notifications/events?limit=20" "" "$TOKEN")"
echo "$EVENTS" | jq
assert_no_error "$EVENTS" "events listed"

echo
echo "2.13) Invalid events limit must fail"
BAD_LIMIT="$(api GET "/api/v2/notifications/events?limit=9999" "" "$TOKEN")"
echo "$BAD_LIMIT" | jq

BAD_LIMIT_ERROR="$(echo "$BAD_LIMIT" | jq -r '.error // empty')"
if [[ "$BAD_LIMIT_ERROR" != "limit must be <= 200" ]]; then
  echo "[KO] expected invalid limit error, got: $BAD_LIMIT_ERROR"
  exit 1
fi
echo "[OK] invalid limit rejected"

echo
echo "2.14) Delete rule"
DELETE_RULE="$(api DELETE "/api/v2/notifications/rules/$RULE_ID" "" "$TOKEN")"
echo "$DELETE_RULE" | jq
assert_no_error "$DELETE_RULE" "rule deleted"
assert_equals "$(echo "$DELETE_RULE" | jq -r '.deleted')" "true" "delete rule flag"

echo
echo "2.15) Delete config"
DELETE_CONFIG="$(api DELETE "/api/v2/notifications/configs/$CONFIG_ID" "" "$TOKEN")"
echo "$DELETE_CONFIG" | jq
assert_no_error "$DELETE_CONFIG" "config deleted"
assert_equals "$(echo "$DELETE_CONFIG" | jq -r '.deleted')" "true" "delete config flag"

echo
echo "2.16) Read deleted config must fail"
READ_DELETED_CONFIG="$(api GET "/api/v2/notifications/configs/$CONFIG_ID" "" "$TOKEN")"
echo "$READ_DELETED_CONFIG" | jq

READ_DELETED_CONFIG_ERROR="$(echo "$READ_DELETED_CONFIG" | jq -r '.error // empty')"
if [[ "$READ_DELETED_CONFIG_ERROR" != "Notification config not found" ]]; then
  echo "[KO] expected not found after config delete, got: $READ_DELETED_CONFIG_ERROR"
  exit 1
fi
echo "[OK] deleted config not found"

echo
echo "=== OK: notifications full workflow passed ==="
