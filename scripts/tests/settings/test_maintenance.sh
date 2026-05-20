#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 maintenance status test ==="
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
echo "2) Read maintenance status"
STATUS="$(api GET "/api/v2/admin/maintenance/status" "" "$TOKEN")"
echo "$STATUS" | jq

assert_jq_true "$STATUS" 'type == "object"' "maintenance returns object"
assert_jq_true "$STATUS" 'has("ok")' "overall ok field present"
assert_jq_true "$STATUS" '.app.version | type == "string"' "app version present"
assert_jq_true "$STATUS" '.app.name | type == "string"' "app name present"
assert_jq_true "$STATUS" '.database.backend | type == "string"' "database backend present"
assert_jq_true "$STATUS" '.database.ok | type == "boolean"' "database ok present"
assert_jq_true "$STATUS" '.database.message | type == "string"' "database message present"
assert_jq_true "$STATUS" '.disk.free_bytes | type == "number"' "disk free_bytes present"
assert_jq_true "$STATUS" '.disk.total_bytes | type == "number"' "disk total_bytes present"
assert_jq_true "$STATUS" '.paths | type == "array"' "paths array present"
assert_jq_true "$STATUS" '.paths | length >= 5' "expected required paths present"

echo
echo "3) Check required paths"
for path_name in data tmp userdata logs torrents_temp_internal; do
  assert_jq_true "$STATUS" ".paths[] | select(.name == \"$path_name\") | .ok == true" "path $path_name OK"
  assert_jq_true "$STATUS" ".paths[] | select(.name == \"$path_name\") | .writable == true" "path $path_name writable"
done

echo
echo "4) Check global health"
assert_jq_true "$STATUS" '.ok == true' "global maintenance status OK"

echo
echo "=== OK: maintenance status workflow passed ==="
