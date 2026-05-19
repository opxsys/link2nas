#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"
TEST_EMAIL_DOMAIN="${TEST_EMAIL_DOMAIN:-test.local}"

# Set to 1 to allow running the test even if a SMTP password is already saved
# (the password cannot be restored — see warning below)
ALLOW_SMTP_PASSWORD_LOSS="${ALLOW_SMTP_PASSWORD_LOSS:-0}"

RUN_ID="$(date +%s)-$$"
SMTP_FAKE_HOST="smtp.unavailable.local"
SMTP_FAKE_PORT=587
SMTP_FAKE_FROM="noreply@unavailable.local"

# ---- helpers ----------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}

unique_email() {
  echo "${1}-${RUN_ID}@${TEST_EMAIL_DOMAIN}"
}

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token="${4:-}"

  if [[ -n "$body" && -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" -H "Content-Type: application/json" -d "$body"
  elif [[ -n "$body" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" -d "$body"
  elif [[ -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" -H "X-Api-Key: $token"
  else
    curl -sS -X "$method" "$BASE_URL$path"
  fi
}

# Executes a request and prints "<http_status>|<body>" on stdout.
api_with_status() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token="${4:-}"
  local tmp
  tmp="$(mktemp /tmp/l2n_smtp_avail_XXXXXX.json)"

  local status
  if [[ -n "$body" && -n "$token" ]]; then
    status="$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" -H "Content-Type: application/json" -d "$body")"
  elif [[ -n "$body" ]]; then
    status="$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" -d "$body")"
  elif [[ -n "$token" ]]; then
    status="$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token")"
  else
    status="$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "$BASE_URL$path")"
  fi

  echo "${status}|$(cat "$tmp")"
  rm -f "$tmp"
}

assert_no_error() {
  local json="$1"
  local label="$2"
  local err
  err="$(echo "$json" | jq -r '.error // empty')"
  if [[ -n "$err" ]]; then
    echo "[KO] $label: $err"
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

assert_body_contains() {
  local body="$1"
  local needle="$2"
  local label="$3"
  if echo "$body" | grep -q "$needle"; then
    echo "[OK] $label: body contains '$needle'"
  else
    echo "[KO] $label: expected body to contain '$needle'"
    echo "$body" | jq 2>/dev/null || echo "$body"
    exit 1
  fi
}

assert_body_not_contains() {
  local body="$1"
  local needle="$2"
  local label="$3"
  if echo "$body" | grep -q "$needle"; then
    echo "[KO] $label: body unexpectedly contains '$needle'"
    echo "$body" | jq 2>/dev/null || echo "$body"
    exit 1
  fi
  echo "[OK] $label: body does not contain '$needle'"
}

assert_json_field() {
  local json="$1"
  local field="$2"
  local expected="$3"
  local label="$4"
  local actual
  local exists

  exists="$(echo "$json" | jq -r "has(\"${field}\")")"
  if [[ "$exists" != "true" ]]; then
    echo "[KO] $label: .${field} missing"
    echo "$json" | jq
    exit 1
  fi

  actual="$(echo "$json" | jq -r ".${field}")"
  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label: .${field} expected '$expected', got '$actual'"
    echo "$json" | jq
    exit 1
  fi

  echo "[OK] $label"
}

# ---- state ------------------------------------------------------------------

ADMIN_TOKEN=""
TEST_USER_ID=""
TEST_USER_TOKEN=""
INITIAL_SMTP_JSON=""

cleanup() {
  local exit_code=$?

  echo
  echo "--- Cleanup ---"

  if [[ -n "$TEST_USER_ID" && -n "$ADMIN_TOKEN" ]]; then
    echo "Deleting test user $TEST_USER_ID ..."
    api DELETE "/api/v2/admin/users/$TEST_USER_ID" "" "$ADMIN_TOKEN" >/dev/null 2>&1 || true
    echo "[INFO] Test user deleted."
  fi

  if [[ -n "$INITIAL_SMTP_JSON" && -n "$ADMIN_TOKEN" ]]; then
    echo "Restoring SMTP settings (without password) ..."
    local restore_payload
    restore_payload="$(echo "$INITIAL_SMTP_JSON" | jq '{
      enabled:    .enabled,
      host:       (.host       // ""),
      port:       (.port       // 587),
      username:   (.username   // ""),
      from_email: (.from_email // ""),
      from_name:  (.from_name  // ""),
      use_tls:    .use_tls,
      use_ssl:    .use_ssl
    }')"
    api PUT "/api/v2/admin/smtp-settings" "$restore_payload" "$ADMIN_TOKEN" >/dev/null 2>&1 || true
    echo "[INFO] SMTP settings restored."

    local had_password
    had_password="$(echo "$INITIAL_SMTP_JSON" | jq -r '.has_password')"
    if [[ "$had_password" == "true" ]]; then
      echo "[WARN] A SMTP password was registered before this test."
      echo "[WARN] The password could not be restored — the API does not expose it."
      echo "[WARN] Re-enter the SMTP password manually in Admin > Email / SMTP."
    fi
  fi

  echo "--- Cleanup done (exit $exit_code) ---"
}
trap cleanup EXIT

# ---- main -------------------------------------------------------------------

echo "=== Link2NAS V2 — email sending availability test ==="
echo "BASE_URL=$BASE_URL"
echo "RUN_ID=$RUN_ID"

need_cmd curl
need_cmd jq

echo
echo "--- Setup: admin login ---"
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  ADMIN_TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
  echo "$LOGIN" | jq
  assert_no_error "$LOGIN" "admin login"
  ADMIN_TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
  if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
    echo "[KO] admin token missing"
    exit 1
  fi
  echo "[OK] admin token received"
fi

echo
echo "--- Setup: save initial SMTP settings ---"
INITIAL_SMTP_JSON="$(api GET "/api/v2/admin/smtp-settings" "" "$ADMIN_TOKEN")"
echo "$INITIAL_SMTP_JSON" | jq
echo "[INFO] Initial SMTP settings saved for cleanup."

INITIAL_HAS_PASSWORD="$(echo "$INITIAL_SMTP_JSON" | jq -r '.has_password')"
if [[ "$INITIAL_HAS_PASSWORD" == "true" ]]; then
  echo
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo "[WARN] A SMTP password is currently saved on this instance."
  echo "[WARN] This script will overwrite SMTP settings and CANNOT restore the password"
  echo "[WARN] because the API does not expose encrypted credentials."
  echo "[WARN] Do NOT run this script against a production instance with a live SMTP."
  echo "[WARN] To proceed anyway, re-run with:  ALLOW_SMTP_PASSWORD_LOSS=1 $0"
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo
  if [[ "$ALLOW_SMTP_PASSWORD_LOSS" != "1" ]]; then
    echo "[KO] Aborting. Set ALLOW_SMTP_PASSWORD_LOSS=1 to override."
    exit 1
  fi
  echo "[WARN] ALLOW_SMTP_PASSWORD_LOSS=1 — continuing despite saved password."
fi

echo
echo "--- Setup: create test user ---"
TEST_USER_EMAIL="$(unique_email smtp-avail)"
CREATE_USER="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$TEST_USER_EMAIL\",
  \"display_name\":\"SMTP Avail Test\",
  \"role\":\"user\",
  \"is_active\":true,
  \"creation_mode\":\"password\",
  \"password\":\"TestUserStrong123!\",
  \"force_password_change\":false
}" "$ADMIN_TOKEN")"
echo "$CREATE_USER" | jq
assert_no_error "$CREATE_USER" "test user created"

TEST_USER_ID="$(echo "$CREATE_USER" | jq -r '.id // empty')"
if [[ -z "$TEST_USER_ID" || "$TEST_USER_ID" == "null" ]]; then
  echo "[KO] test user id missing"
  exit 1
fi
echo "[OK] test user id: $TEST_USER_ID"

echo
echo "--- Setup: login test user ---"
USER_LOGIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$TEST_USER_EMAIL\",
  \"password\":\"TestUserStrong123!\"
}")"
echo "$USER_LOGIN" | jq
assert_no_error "$USER_LOGIN" "test user login"

TEST_USER_TOKEN="$(echo "$USER_LOGIN" | jq -r '.token // empty')"
if [[ -z "$TEST_USER_TOKEN" || "$TEST_USER_TOKEN" == "null" ]]; then
  echo "[KO] test user token missing"
  exit 1
fi
echo "[OK] test user token received"

# =============================================================================
echo
echo "=== 1. GET /api/v2/public/app-info ==="

APP_INFO="$(api GET "/api/v2/public/app-info")"
echo "$APP_INFO" | jq
assert_no_error "$APP_INFO" "app-info reachable without auth"

APP_NAME="$(echo "$APP_INFO" | jq -r '.app_name // empty')"
if [[ -z "$APP_NAME" || "$APP_NAME" == "null" ]]; then
  echo "[KO] app-info: app_name missing or null"
  exit 1
fi
echo "[OK] app-info: app_name present ('$APP_NAME')"

APP_TAGLINE_FIELD="$(echo "$APP_INFO" | jq 'has("app_tagline")')"
assert_equals "$APP_TAGLINE_FIELD" "true" "app-info: app_tagline field present"

EMAIL_AVAIL="$(echo "$APP_INFO" | jq -r '.email_sending_available')"
if [[ "$EMAIL_AVAIL" != "true" && "$EMAIL_AVAIL" != "false" ]]; then
  echo "[KO] app-info: email_sending_available is neither true nor false: '$EMAIL_AVAIL'"
  exit 1
fi
echo "[OK] app-info: email_sending_available is a boolean ('$EMAIL_AVAIL')"

# =============================================================================
echo
echo "=== 2. SMTP disabled — all email actions must return 503 ==="

echo
echo "2a) Disable SMTP (enabled=false, empty host and from_email)"
DISABLE_SMTP="$(api PUT "/api/v2/admin/smtp-settings" '{
  "enabled":    false,
  "host":       "",
  "port":       587,
  "username":   "",
  "from_email": "",
  "from_name":  "",
  "use_tls":    true,
  "use_ssl":    false
}' "$ADMIN_TOKEN")"
echo "$DISABLE_SMTP" | jq
assert_no_error "$DISABLE_SMTP" "SMTP disabled"
assert_json_field "$DISABLE_SMTP" "enabled" "false" "2a) SMTP enabled=false"

echo
echo "2b) app-info must report email_sending_available=false"
APP_INFO_OFF="$(api GET "/api/v2/public/app-info")"
echo "$APP_INFO_OFF" | jq
assert_json_field "$APP_INFO_OFF" "email_sending_available" "false" \
  "2b) app-info email_sending_available=false when SMTP disabled"

echo
echo "2c) POST /api/v2/public/magic-login/request → 503"
RESULT="$(api_with_status POST "/api/v2/public/magic-login/request" "{\"email\":\"$TEST_USER_EMAIL\"}")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_http 503 "$STATUS" "2c) magic-login/request → 503 when SMTP disabled"
assert_body_contains "$BODY" "Email sending is not configured" \
  "2c) magic-login/request → correct error message"

echo
echo "2d) POST /api/v2/admin/users/<id>/invitation/email → 503"
RESULT="$(api_with_status POST "/api/v2/admin/users/$TEST_USER_ID/invitation/email" "" "$ADMIN_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_http 503 "$STATUS" "2d) invitation/email → 503 when SMTP disabled"
assert_body_contains "$BODY" "Email sending is not configured" \
  "2d) invitation/email → correct error message"

echo
echo "2e) POST /api/v2/admin/users/<id>/password-reset-link/email → 503"
RESULT="$(api_with_status POST "/api/v2/admin/users/$TEST_USER_ID/password-reset-link/email" "" "$ADMIN_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_http 503 "$STATUS" "2e) password-reset-link/email → 503 when SMTP disabled"
assert_body_contains "$BODY" "Email sending is not configured" \
  "2e) password-reset-link/email → correct error message"

echo
echo "2f) POST /api/v2/me/request-email-verification → 503"
RESULT="$(api_with_status POST "/api/v2/me/request-email-verification" "" "$TEST_USER_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_http 503 "$STATUS" "2f) request-email-verification → 503 when SMTP disabled"
assert_body_contains "$BODY" "Email sending is not configured" \
  "2f) request-email-verification → correct error message"

echo
echo "2g) POST /api/v2/notifications/configs (channel=email) → 400"
NOTIF_EMAIL="$(unique_email notif)"
RESULT="$(api_with_status POST "/api/v2/notifications/configs" "{
  \"name\":       \"Test Email Channel $RUN_ID\",
  \"channel\":    \"email\",
  \"is_enabled\": true,
  \"config\":     {\"to_email\": \"$NOTIF_EMAIL\"}
}" "$TEST_USER_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_http 400 "$STATUS" "2g) create email notification channel → 400 when SMTP disabled"
assert_body_contains "$BODY" "Email sending is not configured" \
  "2g) create email notification channel → correct error message"

echo
echo "2h) POST /api/v2/notifications/configs (channel=gotify) — must NOT mention SMTP"
RESULT="$(api_with_status POST "/api/v2/notifications/configs" "{
  \"name\":       \"Test Gotify Channel $RUN_ID\",
  \"channel\":    \"gotify\",
  \"is_enabled\": true,
  \"config\":     {\"server_url\": \"https://gotify.unavailable.local\", \"token\": \"fake-token\"}
}" "$TEST_USER_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "HTTP $STATUS"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_body_not_contains "$BODY" "Email sending is not configured" \
  "2h) Gotify channel: error does not mention SMTP"
if [[ "$STATUS" == "201" || "$STATUS" == "200" ]]; then
  GOTIFY_ID="$(echo "$BODY" | jq -r '.id // empty')"
  echo "[OK] 2h) Gotify channel created (HTTP $STATUS) — not blocked by SMTP"
  [[ -n "$GOTIFY_ID" && "$GOTIFY_ID" != "null" ]] && \
    api DELETE "/api/v2/notifications/configs/$GOTIFY_ID" "" "$TEST_USER_TOKEN" >/dev/null 2>&1 || true
else
  echo "[OK] 2h) Gotify channel HTTP $STATUS — error unrelated to SMTP (acceptable)"
fi

echo
echo "2i) POST /api/v2/notifications/configs (channel=webhook) — must NOT mention SMTP"
RESULT="$(api_with_status POST "/api/v2/notifications/configs" "{
  \"name\":       \"Test Webhook Channel $RUN_ID\",
  \"channel\":    \"webhook\",
  \"is_enabled\": true,
  \"config\":     {\"url\": \"https://webhook.unavailable.local/hook\", \"method\": \"POST\"}
}" "$TEST_USER_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "HTTP $STATUS"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_body_not_contains "$BODY" "Email sending is not configured" \
  "2i) Webhook channel: error does not mention SMTP"
if [[ "$STATUS" == "201" || "$STATUS" == "200" ]]; then
  WEBHOOK_ID="$(echo "$BODY" | jq -r '.id // empty')"
  echo "[OK] 2i) Webhook channel created (HTTP $STATUS) — not blocked by SMTP"
  [[ -n "$WEBHOOK_ID" && "$WEBHOOK_ID" != "null" ]] && \
    api DELETE "/api/v2/notifications/configs/$WEBHOOK_ID" "" "$TEST_USER_TOKEN" >/dev/null 2>&1 || true
else
  echo "[OK] 2i) Webhook channel HTTP $STATUS — error unrelated to SMTP (acceptable)"
fi

# =============================================================================
echo
echo "=== 3. Copiable links — must remain available when SMTP is disabled ==="

echo
echo "3a) POST /api/v2/admin/users/<id>/invitation → 201"
RESULT="$(api_with_status POST "/api/v2/admin/users/$TEST_USER_ID/invitation" "" "$ADMIN_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_http 201 "$STATUS" "3a) copiable invitation link → 201 (no SMTP required)"
INVITATION_URL="$(echo "$BODY" | jq -r '.invitation_url // empty')"
if [[ -z "$INVITATION_URL" || "$INVITATION_URL" == "null" ]]; then
  echo "[KO] 3a) invitation_url missing from response"
  exit 1
fi
echo "[OK] 3a) invitation_url present"

echo
echo "3b) POST /api/v2/admin/users/<id>/password-reset-link → 201"
RESULT="$(api_with_status POST "/api/v2/admin/users/$TEST_USER_ID/password-reset-link" "" "$ADMIN_TOKEN")"
STATUS="${RESULT%%|*}"
BODY="${RESULT#*|}"
echo "$BODY" | jq 2>/dev/null || echo "$BODY"
assert_http 201 "$STATUS" "3b) copiable password reset link → 201 (no SMTP required)"
RESET_URL="$(echo "$BODY" | jq -r '.reset_url // empty')"
if [[ -z "$RESET_URL" || "$RESET_URL" == "null" ]]; then
  echo "[KO] 3b) reset_url missing from response"
  exit 1
fi
echo "[OK] 3b) reset_url present"

# =============================================================================
echo
echo "=== 4. SMTP configured minimally (fake host) — email_sending_available must be true ==="

echo
echo "4a) PUT minimal valid SMTP (enabled=true, fake host, no real server)"
ENABLE_SMTP="$(api PUT "/api/v2/admin/smtp-settings" "{
  \"enabled\":    true,
  \"host\":       \"$SMTP_FAKE_HOST\",
  \"port\":       $SMTP_FAKE_PORT,
  \"username\":   \"\",
  \"from_email\": \"$SMTP_FAKE_FROM\",
  \"from_name\":  \"Test\",
  \"use_tls\":    false,
  \"use_ssl\":    false
}" "$ADMIN_TOKEN")"
echo "$ENABLE_SMTP" | jq
assert_no_error "$ENABLE_SMTP" "4a) minimal SMTP saved"
assert_json_field "$ENABLE_SMTP" "enabled"    "true"             "4a) SMTP enabled=true"
assert_json_field "$ENABLE_SMTP" "host"       "$SMTP_FAKE_HOST"  "4a) SMTP host set"
assert_json_field "$ENABLE_SMTP" "from_email" "$SMTP_FAKE_FROM"  "4a) SMTP from_email set"

echo
echo "4b) app-info must report email_sending_available=true"
APP_INFO_ON="$(api GET "/api/v2/public/app-info")"
echo "$APP_INFO_ON" | jq
assert_json_field "$APP_INFO_ON" "email_sending_available" "true" \
  "4b) app-info email_sending_available=true (SMTP enabled with minimal config)"

echo
echo "4c) GET /api/v2/me must include email_sending_available=true"
ME_ON="$(api GET "/api/v2/me" "" "$TEST_USER_TOKEN")"
echo "$ME_ON" | jq
assert_json_field "$ME_ON" "email_sending_available" "true" \
  "4c) GET /me email_sending_available=true"

echo "[INFO] Actual email delivery not tested — '$SMTP_FAKE_HOST' is not a real server."

# =============================================================================
echo
echo "=== 5. GET /api/v2/me reflects SMTP state ==="

echo
echo "5a) Disable SMTP again"
api PUT "/api/v2/admin/smtp-settings" '{
  "enabled":    false,
  "host":       "",
  "port":       587,
  "from_email": "",
  "use_tls":    true,
  "use_ssl":    false
}' "$ADMIN_TOKEN" >/dev/null

echo
echo "5b) GET /api/v2/me must include email_sending_available=false"
ME_OFF="$(api GET "/api/v2/me" "" "$TEST_USER_TOKEN")"
echo "$ME_OFF" | jq
assert_json_field "$ME_OFF" "email_sending_available" "false" \
  "5b) GET /me email_sending_available=false when SMTP disabled"

# =============================================================================
echo
echo "=== OK: email sending availability tests passed ==="
