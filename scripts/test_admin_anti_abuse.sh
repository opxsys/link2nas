#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

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

api_status() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local token="${4:-}"

  if [[ -n "$data" && -n "$token" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$data" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$token" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token"
  else
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path"
  fi
}

assert_http() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "[OK] $label => HTTP $actual"
  else
    echo "[KO] $label: expected HTTP $expected, got HTTP $actual"
    exit 1
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

assert_field() {
  local json="$1"
  local field="$2"
  local label="$3"
  local val
  val="$(echo "$json" | jq -r "$field // empty")"
  if [[ -z "$val" || "$val" == "null" ]]; then
    echo "[KO] $label: field '$field' missing or null"
    echo "$json" | jq
    exit 1
  fi
  echo "[OK] $label (value: $val)"
}

assert_kind_present() {
  local json="$1"
  local kind="$2"
  local found
  found="$(echo "$json" | jq -r --arg k "$kind" '.counters[] | select(.kind==$k) | .kind')"
  if [[ "$found" == "$kind" ]]; then
    echo "[OK] kind '$kind' present"
  else
    echo "[KO] kind '$kind' NOT found in counters"
    echo "$json" | jq '.counters[].kind'
    exit 1
  fi
}

echo "=== Link2NAS V2 Admin Anti-Abuse Test ==="
echo "BASE_URL=$BASE_URL"
echo

need_cmd curl
need_cmd jq

# Step 1: Python compile check
echo "--- Step 1: python3 -m compileall backend"
python3 -m compileall backend -q
echo "[OK] compile backend"
echo

# Step 2: git diff --check
echo "--- Step 2: git diff --check"
git diff --check
echo "[OK] git diff --check"
echo

# Step 3: Auth
echo "--- Step 3: Authenticate admin"
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN_RESP="$(api POST "/api/v2/auth/login" "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
  echo "$LOGIN_RESP" | jq
  assert_no_error "$LOGIN_RESP" "admin login"
  TOKEN="$(echo "$LOGIN_RESP" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "[KO] admin token missing"
    exit 1
  fi
  echo "[OK] admin token received"
fi
echo

# Step 4: GET /anti-abuse => 200
echo "--- Step 4: GET /api/v2/admin/security/anti-abuse"
STATUS="$(api_status GET "/api/v2/admin/security/anti-abuse" "" "$TOKEN")"
assert_http 200 "$STATUS" "GET /anti-abuse"

ANTI_ABUSE="$(api GET "/api/v2/admin/security/anti-abuse" "" "$TOKEN")"
echo "$ANTI_ABUSE" | jq
assert_no_error "$ANTI_ABUSE" "anti-abuse response"
assert_field "$ANTI_ABUSE" ".backend" "backend field"
assert_field "$ANTI_ABUSE" '.redis_enabled | tostring' "redis_enabled field"
echo

# Step 5: Verify expected kinds
echo "--- Step 5: Verify expected kinds"
EXPECTED_KINDS=(
  login
  magic_login_request
  magic_login_confirm
  password_reset_confirm
  email_verification_request
  email_verification_confirm
  admin_invitation_email
  admin_password_reset_email
  qbittorrent_add
)
for kind in "${EXPECTED_KINDS[@]}"; do
  assert_kind_present "$ANTI_ABUSE" "$kind"
done
echo

# Step 6: Trigger login counter
echo "--- Step 6: Trigger login rate limit counter"
for i in 1 2 3; do
  curl -s -o /dev/null -X POST "$BASE_URL/api/v2/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"rate-anti-abuse-test@test.local","password":"wrong"}' || true
done
echo "[OK] Login counter triggered"
echo

# Step 7: Verify counter visibility or proper unavailability
echo "--- Step 7: Re-fetch and check login counter state"
ANTI_ABUSE2="$(api GET "/api/v2/admin/security/anti-abuse" "" "$TOKEN")"
LOGIN_COUNTER="$(echo "$ANTI_ABUSE2" | jq -r '.counters[] | select(.kind=="login")')"
LOGIN_STATUS="$(echo "$LOGIN_COUNTER" | jq -r '.status')"
if [[ "$LOGIN_STATUS" == "ok" ]]; then
  HITS="$(echo "$LOGIN_COUNTER" | jq -r '.estimated_hits')"
  echo "[OK] login counter status=ok, estimated_hits=$HITS"
elif [[ "$LOGIN_STATUS" == "unavailable" ]]; then
  echo "[OK] login counter status=unavailable (backend limitation — acceptable)"
else
  echo "[KO] Unexpected login counter status: $LOGIN_STATUS"
  exit 1
fi
echo

# Step 8: POST reset/<kind>
echo "--- Step 8: POST /api/v2/admin/security/anti-abuse/reset/login"
STATUS="$(api_status POST "/api/v2/admin/security/anti-abuse/reset/login" "" "$TOKEN")"
assert_http 200 "$STATUS" "POST /anti-abuse/reset/login"
RESET_KIND="$(api POST "/api/v2/admin/security/anti-abuse/reset/login" "" "$TOKEN")"
echo "$RESET_KIND" | jq
RESET_OK="$(echo "$RESET_KIND" | jq -r '.ok')"
if [[ "$RESET_OK" != "true" ]]; then
  echo "[KO] reset/login: ok != true"
  exit 1
fi
echo "[OK] reset/login"
echo

# Step 9: POST reset all
echo "--- Step 9: POST /api/v2/admin/security/anti-abuse/reset"
STATUS="$(api_status POST "/api/v2/admin/security/anti-abuse/reset" "" "$TOKEN")"
assert_http 200 "$STATUS" "POST /anti-abuse/reset"
RESET_ALL="$(api POST "/api/v2/admin/security/anti-abuse/reset" "" "$TOKEN")"
echo "$RESET_ALL" | jq
RESET_ALL_OK="$(echo "$RESET_ALL" | jq -r '.ok')"
if [[ "$RESET_ALL_OK" != "true" ]]; then
  echo "[KO] reset all: ok != true"
  exit 1
fi
echo "[OK] reset all"
echo

# Step 10: Non-admin access => 401 or 403
echo "--- Step 10: Non-admin access control"
STATUS_NOAUTH="$(api_status GET "/api/v2/admin/security/anti-abuse")"
if [[ "$STATUS_NOAUTH" == "401" || "$STATUS_NOAUTH" == "403" ]]; then
  echo "[OK] No token => HTTP $STATUS_NOAUTH"
else
  echo "[KO] No token: expected 401 or 403, got HTTP $STATUS_NOAUTH"
  exit 1
fi
echo

# Step 11: Unknown kind => 404
echo "--- Step 11: Reset unknown kind => 404"
STATUS_UNK="$(api_status POST "/api/v2/admin/security/anti-abuse/reset/nonexistent_kind" "" "$TOKEN")"
if [[ "$STATUS_UNK" == "404" ]]; then
  echo "[OK] Unknown kind => HTTP 404"
else
  echo "[KO] Unknown kind: expected 404, got HTTP $STATUS_UNK"
  exit 1
fi
echo

# Step 12: Final compile check
echo "--- Step 12: Final python3 -m compileall backend"
python3 -m compileall backend -q
echo "[OK] compile backend (final)"
echo

# Step 13: Final git diff --check
echo "--- Step 13: Final git diff --check"
git diff --check
echo "[OK] git diff --check (final)"
echo

echo "=== All anti-abuse tests passed ==="
