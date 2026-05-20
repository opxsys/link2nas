#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 cleanup settings + run test ==="
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

fail_json() {
  local label="$1"
  local json="$2"
  echo "[KO] $label"
  echo "$json" | jq
  exit 1
}

assert_jq_true() {
  local json="$1"
  local expr="$2"
  local label="$3"

  if echo "$json" | jq -e "$expr" >/dev/null; then
    echo "[OK] $label"
  else
    fail_json "$label" "$json"
  fi
}

ensure_first_admin() {
  echo
  echo "0) Ensure first admin exists"

  local setup_status
  setup_status="$(api GET "/api/v2/setup/status")"
  echo "$setup_status" | jq

  local setup_required
  setup_required="$(echo "$setup_status" | jq -r '.setup_required')"

  if [[ "$setup_required" == "true" ]]; then
    echo "[INFO] Creating first admin"

    local created
    created="$(api POST "/api/v2/setup/first-admin" "{
      \"email\":\"$ADMIN_EMAIL\",
      \"display_name\":\"Admin\",
      \"password\":\"$ADMIN_PASSWORD\"
    }")"

    echo "$created" | jq
    assert_jq_true "$created" 'has("id") or has("user") or (.ok == true)' "first admin created"
  else
    echo "[INFO] Setup already completed"
  fi
}

need_cmd curl
need_cmd jq

ensure_first_admin

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
  TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    fail_json "admin login" "$LOGIN"
  fi
  echo "[OK] admin login"
fi

echo
echo "2) Read cleanup settings"
SETTINGS_BEFORE="$(api GET "/api/v2/admin/app-settings/cleanup" "" "$TOKEN")"
echo "$SETTINGS_BEFORE" | jq

assert_jq_true "$SETTINGS_BEFORE" 'type == "object"' "cleanup settings returns object"
assert_jq_true "$SETTINGS_BEFORE" '.retention | type == "object"' "retention object present"
assert_jq_true "$SETTINGS_BEFORE" '.retention.torrent_tmp_days | type == "number"' "torrent_tmp_days present"
assert_jq_true "$SETTINGS_BEFORE" '.retention.completed_jobs_days | type == "number"' "completed_jobs_days present"
assert_jq_true "$SETTINGS_BEFORE" '.retention.failed_jobs_days | type == "number"' "failed_jobs_days present"
assert_jq_true "$SETTINGS_BEFORE" '.retention.cancelled_jobs_days | type == "number"' "cancelled_jobs_days present"
assert_jq_true "$SETTINGS_BEFORE" '.retention.expired_tokens_days | type == "number"' "expired_tokens_days present"

ORIGINAL_RETENTION="$(echo "$SETTINGS_BEFORE" | jq -c '.retention')"

echo
echo "3) Save cleanup settings with test values"
SAVE_PAYLOAD='{
  "retention": {
    "torrent_tmp_days": 7,
    "completed_jobs_days": 30,
    "failed_jobs_days": 30,
    "cancelled_jobs_days": 15,
    "expired_tokens_days": 7
  }
}'

SAVED="$(api PUT "/api/v2/admin/app-settings/cleanup" "$SAVE_PAYLOAD" "$TOKEN")"
echo "$SAVED" | jq

assert_jq_true "$SAVED" '.retention.torrent_tmp_days == 7' "saved torrent_tmp_days"
assert_jq_true "$SAVED" '.retention.completed_jobs_days == 30' "saved completed_jobs_days"
assert_jq_true "$SAVED" '.retention.failed_jobs_days == 30' "saved failed_jobs_days"
assert_jq_true "$SAVED" '.retention.cancelled_jobs_days == 15' "saved cancelled_jobs_days"
assert_jq_true "$SAVED" '.retention.expired_tokens_days == 7' "saved expired_tokens_days"

echo
echo "4) Re-read cleanup settings"
SETTINGS_AFTER="$(api GET "/api/v2/admin/app-settings/cleanup" "" "$TOKEN")"
echo "$SETTINGS_AFTER" | jq

assert_jq_true "$SETTINGS_AFTER" '.retention.torrent_tmp_days == 7' "persisted torrent_tmp_days"
assert_jq_true "$SETTINGS_AFTER" '.retention.completed_jobs_days == 30' "persisted completed_jobs_days"
assert_jq_true "$SETTINGS_AFTER" '.retention.failed_jobs_days == 30' "persisted failed_jobs_days"
assert_jq_true "$SETTINGS_AFTER" '.retention.cancelled_jobs_days == 15' "persisted cancelled_jobs_days"
assert_jq_true "$SETTINGS_AFTER" '.retention.expired_tokens_days == 7' "persisted expired_tokens_days"

echo
echo "5) Run cleanup manually"
RUN_RESULT="$(api POST "/api/v2/admin/cleanup/run" "{}" "$TOKEN")"
echo "$RUN_RESULT" | jq

assert_jq_true "$RUN_RESULT" '.enabled | type == "boolean"' "cleanup enabled field present"
assert_jq_true "$RUN_RESULT" '.started_at | type == "string"' "cleanup started_at present"
assert_jq_true "$RUN_RESULT" '.finished_at | type == "string"' "cleanup finished_at present"
assert_jq_true "$RUN_RESULT" '.tokens_deleted | type == "number"' "tokens_deleted present"
assert_jq_true "$RUN_RESULT" '.completed_jobs_deleted | type == "number"' "completed_jobs_deleted present"
assert_jq_true "$RUN_RESULT" '.failed_jobs_deleted | type == "number"' "failed_jobs_deleted present"
assert_jq_true "$RUN_RESULT" '.cancelled_jobs_deleted | type == "number"' "cancelled_jobs_deleted present"
assert_jq_true "$RUN_RESULT" '.temp_files_deleted | type == "number"' "temp_files_deleted present"
assert_jq_true "$RUN_RESULT" '.temp_files_errors | type == "array"' "temp_files_errors present"

echo
echo "6) Restore original cleanup settings"
RESTORE_PAYLOAD="$(jq -n --argjson retention "$ORIGINAL_RETENTION" '{retention: $retention}')"
RESTORED="$(api PUT "/api/v2/admin/app-settings/cleanup" "$RESTORE_PAYLOAD" "$TOKEN")"
echo "$RESTORED" | jq

assert_jq_true "$RESTORED" '.retention | type == "object"' "original retention restored"

echo
echo "=== OK: cleanup settings + run workflow passed ==="
