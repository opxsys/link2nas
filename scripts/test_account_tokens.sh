#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"
USER_EMAIL="${USER_EMAIL:-user1@test.local}"
USER_TEMP_PASSWORD="${USER_TEMP_PASSWORD:-TempPassword123!}"
USER_INVITE_PASSWORD="${USER_INVITE_PASSWORD:-NewPassword123!}"
USER_RESET_PASSWORD="${USER_RESET_PASSWORD:-ResetPassword123!}"
USER_MANUAL_RESET_PASSWORD="${USER_MANUAL_RESET_PASSWORD:-ManualReset123!}"

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

extract_token_from_url() {
  local url="$1"
  echo "$url" | sed -n 's/.*token=\([^&]*\).*/\1/p'
}

echo "=== Link2NAS V2 account tokens test ==="
echo "BASE_URL=$BASE_URL"

need_cmd curl
need_cmd jq
need_cmd sed

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
echo "4) Create normal user"
CREATE_USER="$(api POST "/api/v2/admin/users" "{
  \"email\":\"$USER_EMAIL\",
  \"display_name\":\"User One\",
  \"password\":\"$USER_TEMP_PASSWORD\",
  \"email_verified\":false
}" "$ADMIN_TOKEN")"
echo "$CREATE_USER" | jq

CREATE_USER_ERROR="$(echo "$CREATE_USER" | jq -r '.error // empty')"
if [[ "$CREATE_USER_ERROR" == "A user with this email already exists" ]]; then
  echo "[INFO] User already exists, searching user id from list"
  USERS="$(api GET "/api/v2/admin/users" "" "$ADMIN_TOKEN")"
  USER_ID="$(echo "$USERS" | jq -r ".[] | select(.email == \"$USER_EMAIL\") | .id" | head -n 1)"
else
  assert_no_error "$CREATE_USER" "user created"
  USER_ID="$(echo "$CREATE_USER" | jq -r '.id')"
fi

if [[ -z "${USER_ID:-}" || "$USER_ID" == "null" ]]; then
  echo "[KO] user id missing"
  exit 1
fi
echo "[OK] user id: $USER_ID"

echo
echo "5) Create invitation link"
INVITE_RESPONSE="$(api POST "/api/v2/admin/users/$USER_ID/invitation" "" "$ADMIN_TOKEN")"
echo "$INVITE_RESPONSE" | jq
assert_no_error "$INVITE_RESPONSE" "invitation token created"

INVITE_URL="$(echo "$INVITE_RESPONSE" | jq -r '.invitation_url // empty')"
INVITE_TOKEN="$(extract_token_from_url "$INVITE_URL")"

if [[ -z "$INVITE_TOKEN" ]]; then
  echo "[KO] invitation token missing from URL: $INVITE_URL"
  exit 1
fi
echo "[OK] invitation token extracted"

echo
echo "6) Check invitation token status"
INVITE_STATUS="$(api GET "/api/v2/public/tokens/$INVITE_TOKEN/status")"
echo "$INVITE_STATUS" | jq
assert_no_error "$INVITE_STATUS" "invitation token valid"

INVITE_TYPE="$(echo "$INVITE_STATUS" | jq -r '.token_type')"
assert_equals "$INVITE_TYPE" "invitation" "invitation token type"

echo
echo "7) Accept invitation"
ACCEPT_INVITE="$(api POST "/api/v2/public/invitations/accept" "{
  \"token\":\"$INVITE_TOKEN\",
  \"password\":\"$USER_INVITE_PASSWORD\"
}")"
echo "$ACCEPT_INVITE" | jq
assert_no_error "$ACCEPT_INVITE" "invitation accepted"

echo
echo "8) Reuse invitation token must fail"
REUSE_INVITE="$(api GET "/api/v2/public/tokens/$INVITE_TOKEN/status")"
echo "$REUSE_INVITE" | jq
REUSE_ERROR="$(echo "$REUSE_INVITE" | jq -r '.error // empty')"

if [[ "$REUSE_ERROR" != "Token already used" ]]; then
  echo "[KO] expected 'Token already used', got '$REUSE_ERROR'"
  exit 1
fi
echo "[OK] invitation token cannot be reused"

echo
echo "9) Login user after invitation"
LOGIN_USER="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$USER_EMAIL\",
  \"password\":\"$USER_INVITE_PASSWORD\"
}")"
echo "$LOGIN_USER" | jq
assert_no_error "$LOGIN_USER" "user login after invitation"

FORCE_CHANGE="$(echo "$LOGIN_USER" | jq -r '.user.force_password_change // false')"
assert_equals "$FORCE_CHANGE" "false" "force_password_change false after invitation"

echo
echo "10) Create password reset link"
RESET_LINK_RESPONSE="$(api POST "/api/v2/admin/users/$USER_ID/password-reset-link" "" "$ADMIN_TOKEN")"
echo "$RESET_LINK_RESPONSE" | jq
assert_no_error "$RESET_LINK_RESPONSE" "password reset token created"

RESET_URL="$(echo "$RESET_LINK_RESPONSE" | jq -r '.reset_url // empty')"
RESET_TOKEN="$(extract_token_from_url "$RESET_URL")"

if [[ -z "$RESET_TOKEN" ]]; then
  echo "[KO] reset token missing from URL: $RESET_URL"
  exit 1
fi
echo "[OK] reset token extracted"

echo
echo "11) Check password reset token status"
RESET_STATUS="$(api GET "/api/v2/public/tokens/$RESET_TOKEN/status")"
echo "$RESET_STATUS" | jq
assert_no_error "$RESET_STATUS" "password reset token valid"

RESET_TYPE="$(echo "$RESET_STATUS" | jq -r '.token_type')"
assert_equals "$RESET_TYPE" "password_reset" "password reset token type"

echo
echo "12) Confirm password reset"
CONFIRM_RESET="$(api POST "/api/v2/public/password-reset/confirm" "{
  \"token\":\"$RESET_TOKEN\",
  \"password\":\"$USER_RESET_PASSWORD\"
}")"
echo "$CONFIRM_RESET" | jq
assert_no_error "$CONFIRM_RESET" "password reset confirmed"

echo
echo "13) Reuse reset token must fail"
REUSE_RESET="$(api GET "/api/v2/public/tokens/$RESET_TOKEN/status")"
echo "$REUSE_RESET" | jq
REUSE_RESET_ERROR="$(echo "$REUSE_RESET" | jq -r '.error // empty')"

if [[ "$REUSE_RESET_ERROR" != "Token already used" ]]; then
  echo "[KO] expected 'Token already used', got '$REUSE_RESET_ERROR'"
  exit 1
fi
echo "[OK] reset token cannot be reused"

echo
echo "14) Login user after reset link"
LOGIN_AFTER_RESET="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$USER_EMAIL\",
  \"password\":\"$USER_RESET_PASSWORD\"
}")"
echo "$LOGIN_AFTER_RESET" | jq
assert_no_error "$LOGIN_AFTER_RESET" "user login after reset link"

FORCE_CHANGE_AFTER_RESET="$(echo "$LOGIN_AFTER_RESET" | jq -r '.user.force_password_change // false')"
assert_equals "$FORCE_CHANGE_AFTER_RESET" "false" "force_password_change false after reset link"

echo
echo "15) Manual admin password reset"
MANUAL_RESET="$(api POST "/api/v2/admin/users/$USER_ID/reset-password" "{
  \"password\":\"$USER_MANUAL_RESET_PASSWORD\"
}" "$ADMIN_TOKEN")"
echo "$MANUAL_RESET" | jq
assert_no_error "$MANUAL_RESET" "manual admin reset"

echo
echo "16) Login user after manual reset"
LOGIN_AFTER_MANUAL_RESET="$(api POST "/api/v2/auth/login" "{
  \"email\":\"$USER_EMAIL\",
  \"password\":\"$USER_MANUAL_RESET_PASSWORD\"
}")"
echo "$LOGIN_AFTER_MANUAL_RESET" | jq
assert_no_error "$LOGIN_AFTER_MANUAL_RESET" "user login after manual reset"

FORCE_CHANGE_AFTER_MANUAL="$(echo "$LOGIN_AFTER_MANUAL_RESET" | jq -r '.user.force_password_change // false')"
assert_equals "$FORCE_CHANGE_AFTER_MANUAL" "true" "force_password_change true after manual admin reset"

echo
echo "=== OK: account token workflow passed ==="
