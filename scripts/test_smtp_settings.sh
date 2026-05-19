#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

SMTP_HOST="${SMTP_HOST:-smtp.example.local}"
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_USERNAME="${SMTP_USERNAME:-test-user}"
SMTP_PASSWORD="${SMTP_PASSWORD:-secret-password}"
SMTP_FROM_EMAIL="${SMTP_FROM_EMAIL:-noreply@example.com}"
SMTP_FROM_NAME="${SMTP_FROM_NAME:-Link2NAS}"

DB_PATH="${DB_PATH:-data/link2nas_v2.sqlite3}"
CHECK_SQLITE="${CHECK_SQLITE:-auto}"

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
  error="$(echo "$json" | jq -r '.error // empty')"

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

assert_json_has_no_password() {
  local json="$1"
  local label="$2"

  if echo "$json" | jq -e 'has("password")' >/dev/null; then
    echo "[KO] $label: response exposes password"
    echo "$json" | jq
    exit 1
  fi

  if echo "$json" | jq -e 'has("encrypted_password")' >/dev/null; then
    echo "[KO] $label: response exposes encrypted_password"
    echo "$json" | jq
    exit 1
  fi

  echo "[OK] $label does not expose password fields"
}

echo "=== Link2NAS V2 SMTP settings API test ==="
echo "BASE_URL=$BASE_URL"

need_cmd curl
need_cmd jq

echo
echo "1) Setup status"
SETUP_STATUS="$(api GET "/api/v2/setup/status")"
echo "$SETUP_STATUS" | jq
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo
  echo "2) Create first admin"
  CREATE_ADMIN="$(api POST "/api/v2/setup/first-admin" "{
    \"email\":\"$ADMIN_EMAIL\",
    \"display_name\":\"Admin\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  echo "$CREATE_ADMIN" | jq
  assert_no_error "$CREATE_ADMIN" "first admin created"
else
  echo "[INFO] Setup already completed, skipping first admin creation"
fi

echo
echo "3) Login admin"
ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  ADMIN_TOKEN="$ADMIN_API_KEY"
else
  echo "[INFO] No admin API key provided, logging in with ADMIN_EMAIL/ADMIN_PASSWORD"
  LOGIN_ADMIN="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$ADMIN_EMAIL\",
  \"password\":\"$ADMIN_PASSWORD\"
}")"
  echo "$LOGIN_ADMIN" | jq
  assert_no_error "$LOGIN_ADMIN" "admin login"
  ADMIN_TOKEN="$(echo "$LOGIN_ADMIN" | jq -r '.token // empty')"
  if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
    echo "[KO] admin token missing"
    exit 1
  fi
  echo "[OK] admin token received"
fi

echo
echo "4) Read default SMTP settings"
DEFAULT_SMTP="$(api GET "/api/v2/admin/smtp-settings" "" "$ADMIN_TOKEN")"
echo "$DEFAULT_SMTP" | jq
assert_no_error "$DEFAULT_SMTP" "default SMTP settings read"
assert_json_has_no_password "$DEFAULT_SMTP" "default SMTP settings"

DEFAULT_ENABLED="$(echo "$DEFAULT_SMTP" | jq -r '.enabled')"
DEFAULT_PORT="$(echo "$DEFAULT_SMTP" | jq -r '.port')"
DEFAULT_HAS_PASSWORD="$(echo "$DEFAULT_SMTP" | jq -r '.has_password')"

assert_equals "$DEFAULT_ENABLED" "false" "default enabled=false"
assert_equals "$DEFAULT_PORT" "587" "default port=587"
assert_equals "$DEFAULT_HAS_PASSWORD" "false" "default has_password=false"

echo
echo "5) Save disabled SMTP settings with password"
SAVE_DISABLED="$(api PUT "/api/v2/admin/smtp-settings" "{
  \"enabled\": false,
  \"host\": \"$SMTP_HOST\",
  \"port\": $SMTP_PORT,
  \"username\": \"$SMTP_USERNAME\",
  \"password\": \"$SMTP_PASSWORD\",
  \"from_email\": \"$SMTP_FROM_EMAIL\",
  \"from_name\": \"$SMTP_FROM_NAME\",
  \"use_tls\": true,
  \"use_ssl\": false
}" "$ADMIN_TOKEN")"
echo "$SAVE_DISABLED" | jq
assert_no_error "$SAVE_DISABLED" "disabled SMTP settings saved"
assert_json_has_no_password "$SAVE_DISABLED" "saved SMTP settings"

HAS_PASSWORD="$(echo "$SAVE_DISABLED" | jq -r '.has_password')"
HOST="$(echo "$SAVE_DISABLED" | jq -r '.host')"
USERNAME="$(echo "$SAVE_DISABLED" | jq -r '.username')"
FROM_EMAIL="$(echo "$SAVE_DISABLED" | jq -r '.from_email')"
USE_TLS="$(echo "$SAVE_DISABLED" | jq -r '.use_tls')"
USE_SSL="$(echo "$SAVE_DISABLED" | jq -r '.use_ssl')"

assert_equals "$HAS_PASSWORD" "true" "has_password=true after save"
assert_equals "$HOST" "$SMTP_HOST" "host saved"
assert_equals "$USERNAME" "$SMTP_USERNAME" "username saved"
assert_equals "$FROM_EMAIL" "$SMTP_FROM_EMAIL" "from_email saved"
assert_equals "$USE_TLS" "true" "use_tls=true"
assert_equals "$USE_SSL" "false" "use_ssl=false"

echo
echo "6) Read SMTP settings again"
READ_AGAIN="$(api GET "/api/v2/admin/smtp-settings" "" "$ADMIN_TOKEN")"
echo "$READ_AGAIN" | jq
assert_no_error "$READ_AGAIN" "SMTP settings read again"
assert_json_has_no_password "$READ_AGAIN" "read SMTP settings"

READ_HAS_PASSWORD="$(echo "$READ_AGAIN" | jq -r '.has_password')"
assert_equals "$READ_HAS_PASSWORD" "true" "has_password persisted"

echo
echo "7) Update SMTP settings without password, password must be preserved"
SAVE_NO_PASSWORD="$(api PUT "/api/v2/admin/smtp-settings" "{
  \"enabled\": false,
  \"host\": \"$SMTP_HOST\",
  \"port\": $SMTP_PORT,
  \"username\": \"$SMTP_USERNAME\",
  \"from_email\": \"$SMTP_FROM_EMAIL\",
  \"from_name\": \"Link2NAS Updated\",
  \"use_tls\": true,
  \"use_ssl\": false
}" "$ADMIN_TOKEN")"
echo "$SAVE_NO_PASSWORD" | jq
assert_no_error "$SAVE_NO_PASSWORD" "SMTP settings updated without password"
assert_json_has_no_password "$SAVE_NO_PASSWORD" "updated SMTP settings"

PRESERVED_HAS_PASSWORD="$(echo "$SAVE_NO_PASSWORD" | jq -r '.has_password')"
UPDATED_FROM_NAME="$(echo "$SAVE_NO_PASSWORD" | jq -r '.from_name')"

assert_equals "$PRESERVED_HAS_PASSWORD" "true" "password preserved when omitted"
assert_equals "$UPDATED_FROM_NAME" "Link2NAS Updated" "from_name updated"

echo
echo "8) Enabling SMTP without host must fail"
ENABLE_WITHOUT_HOST="$(api PUT "/api/v2/admin/smtp-settings" "{
  \"enabled\": true,
  \"host\": \"\",
  \"port\": $SMTP_PORT,
  \"username\": \"$SMTP_USERNAME\",
  \"from_email\": \"$SMTP_FROM_EMAIL\",
  \"from_name\": \"$SMTP_FROM_NAME\",
  \"use_tls\": true,
  \"use_ssl\": false
}" "$ADMIN_TOKEN")"
echo "$ENABLE_WITHOUT_HOST" | jq

ERROR_WITHOUT_HOST="$(echo "$ENABLE_WITHOUT_HOST" | jq -r '.error // empty')"
if [[ "$ERROR_WITHOUT_HOST" != "SMTP host is required when enabled" ]]; then
  echo "[KO] expected SMTP host validation error, got: $ERROR_WITHOUT_HOST"
  exit 1
fi
echo "[OK] enabling SMTP without host is rejected"

echo
echo "9) Enabling SMTP with TLS and SSL together must fail"
TLS_SSL_ERROR_RESPONSE="$(api PUT "/api/v2/admin/smtp-settings" "{
  \"enabled\": true,
  \"host\": \"$SMTP_HOST\",
  \"port\": $SMTP_PORT,
  \"username\": \"$SMTP_USERNAME\",
  \"from_email\": \"$SMTP_FROM_EMAIL\",
  \"from_name\": \"$SMTP_FROM_NAME\",
  \"use_tls\": true,
  \"use_ssl\": true
}" "$ADMIN_TOKEN")"
echo "$TLS_SSL_ERROR_RESPONSE" | jq

TLS_SSL_ERROR="$(echo "$TLS_SSL_ERROR_RESPONSE" | jq -r '.error // empty')"
if [[ "$TLS_SSL_ERROR" != "use_tls and use_ssl cannot both be enabled" ]]; then
  echo "[KO] expected TLS/SSL validation error, got: $TLS_SSL_ERROR"
  exit 1
fi
echo "[OK] TLS and SSL together are rejected"

echo
echo "10) Save enabled SMTP settings"
SAVE_ENABLED="$(api PUT "/api/v2/admin/smtp-settings" "{
  \"enabled\": true,
  \"host\": \"$SMTP_HOST\",
  \"port\": $SMTP_PORT,
  \"username\": \"$SMTP_USERNAME\",
  \"password\": \"$SMTP_PASSWORD\",
  \"from_email\": \"$SMTP_FROM_EMAIL\",
  \"from_name\": \"$SMTP_FROM_NAME\",
  \"use_tls\": true,
  \"use_ssl\": false
}" "$ADMIN_TOKEN")"
echo "$SAVE_ENABLED" | jq
assert_no_error "$SAVE_ENABLED" "enabled SMTP settings saved"
assert_json_has_no_password "$SAVE_ENABLED" "enabled SMTP settings"

ENABLED="$(echo "$SAVE_ENABLED" | jq -r '.enabled')"
assert_equals "$ENABLED" "true" "enabled=true saved"

if [[ "$CHECK_SQLITE" == "true" || ( "$CHECK_SQLITE" == "auto" && -f "$DB_PATH" && -x "$(command -v sqlite3 || true)" ) ]]; then
  echo
  echo "11) SQLite encrypted password check"
  need_cmd sqlite3

  DB_PASSWORD_VALUE="$(sqlite3 "$DB_PATH" "select encrypted_password from smtp_settings limit 1;")"

  if [[ -z "$DB_PASSWORD_VALUE" ]]; then
    echo "[KO] encrypted_password is empty in SQLite"
    exit 1
  fi

  if [[ "$DB_PASSWORD_VALUE" == "$SMTP_PASSWORD" ]]; then
    echo "[KO] SMTP password stored in clear text"
    exit 1
  fi

  if [[ "$DB_PASSWORD_VALUE" != enc::* ]]; then
    echo "[KO] SMTP password does not look encrypted: $DB_PASSWORD_VALUE"
    exit 1
  fi

  echo "[OK] SMTP password encrypted in SQLite"
else
  echo
  echo "[INFO] SQLite encrypted password check skipped"
fi

echo
echo "12) SMTP send test behavior"
TEST_SEND="$(api POST "/api/v2/admin/smtp-settings/test" "" "$ADMIN_TOKEN")"
echo "$TEST_SEND" | jq

TEST_OK="$(echo "$TEST_SEND" | jq -r '.ok // false')"
TEST_ERROR="$(echo "$TEST_SEND" | jq -r '.error // empty')"

if [[ "$TEST_OK" == "true" ]]; then
  echo "[OK] SMTP test email sent"
else
  echo "[INFO] SMTP test did not send successfully: ${TEST_ERROR:-unknown error}"
  echo "[INFO] This is acceptable with fake SMTP credentials."
fi

echo
echo "=== OK: SMTP settings API workflow passed ==="
