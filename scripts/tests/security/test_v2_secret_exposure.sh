#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
BACKEND="${V2_DATABASE_BACKEND:-sqlite}"

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

echo "=== Link2NAS V2 secret exposure test ==="
echo "Backend=$BACKEND"
echo "BASE_URL=$BASE_URL"
echo

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token="${4:-}"

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

fail() {
  echo "[KO] $1"
  [[ "${2:-}" != "" ]] && echo "$2" | jq . 2>/dev/null || true
  exit 1
}

ok() {
  echo "[OK] $1"
}

assert_no_error() {
  local json="$1"
  local label="$2"
  local err
  err="$(echo "$json" | jq -r '.error // empty')"
  [[ -z "$err" ]] || fail "$label" "$json"
  ok "$label"
}

assert_not_contains_secret() {
  local json="$1"
  local secret="$2"
  local label="$3"

  if echo "$json" | grep -Fq "$secret"; then
    fail "$label leaked secret" "$json"
  fi

  ok "$label did not leak secret"
}

assert_field_absent() {
  local json="$1"
  local jq_filter="$2"
  local label="$3"

  local value
  value="$(echo "$json" | jq -r "$jq_filter // empty")"

  if [[ -n "$value" && "$value" != "null" ]]; then
    fail "$label should be absent/null" "$json"
  fi

  ok "$label absent/null"
}

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
  [[ -n "$TOKEN" && "$TOKEN" != "null" ]] || fail "admin token missing" "$LOGIN"
  ok "admin token received"
fi

PROVIDER_SECRET="secret-provider-api-key-$(date +%s)-$RANDOM"
NAS_PASSWORD="secret-nas-password-$(date +%s)-$RANDOM"
SMTP_PASSWORD="secret-smtp-password-$(date +%s)-$RANDOM"
GOTIFY_TOKEN="secret-gotify-token-$(date +%s)-$RANDOM"
WEBHOOK_SECRET="secret-webhook-header-$(date +%s)-$RANDOM"

echo
echo "2) Save provider config with secret API key"
PROVIDER_SAVE="$(api POST "/api/v2/providers" "{
  \"provider_name\":\"realdebrid\",
  \"api_key\":\"$PROVIDER_SECRET\",
  \"is_enabled\":true,
  \"is_default\":true
}" "$TOKEN")"
echo "$PROVIDER_SAVE" | jq
assert_no_error "$PROVIDER_SAVE" "provider saved"
assert_not_contains_secret "$PROVIDER_SAVE" "$PROVIDER_SECRET" "provider save response"
assert_field_absent "$PROVIDER_SAVE" '.api_key' "provider api_key"
assert_field_absent "$PROVIDER_SAVE" '.encrypted_api_key' "provider encrypted_api_key"

PROVIDER_READ="$(api GET "/api/v2/providers/realdebrid" "" "$TOKEN")"
echo "$PROVIDER_READ" | jq
assert_no_error "$PROVIDER_READ" "provider read"
assert_not_contains_secret "$PROVIDER_READ" "$PROVIDER_SECRET" "provider read response"
[[ "$(echo "$PROVIDER_READ" | jq -r '.has_api_key')" == "true" ]] || fail "provider has_api_key expected true" "$PROVIDER_READ"

echo
echo "3) Save Synology destination with password"

DEST_CONFIG_JSON="$(jq -nc \
  --arg url "https://nas.example.local:5001" \
  --arg username "test-user" \
  --arg password "$NAS_PASSWORD" \
  --arg path "/downloads" \
  '{
    synology_url: $url,
    username: $username,
    password: $password,
    destination_path: $path
  }'
)"

DEST_SAVE="$(api POST "/api/v2/destinations" "$(jq -nc \
  --arg config_json "$DEST_CONFIG_JSON" \
  '{
    destination_name: "nas",
    is_enabled: true,
    is_default: true,
    config_json: $config_json
  }'
)" "$TOKEN")"

echo "$DEST_SAVE" | jq
assert_no_error "$DEST_SAVE" "destination saved"
assert_not_contains_secret "$DEST_SAVE" "$NAS_PASSWORD" "destination save response"
assert_field_absent "$DEST_SAVE" '.config.password' "destination config.password"
assert_field_absent "$DEST_SAVE" '.config.encrypted_password' "destination config.encrypted_password"

DEST_READ="$(api GET "/api/v2/destinations/synology" "" "$TOKEN")"
echo "$DEST_READ" | jq
assert_no_error "$DEST_READ" "destination read"
assert_not_contains_secret "$DEST_READ" "$NAS_PASSWORD" "destination read response"
[[ "$(echo "$DEST_READ" | jq -r '.config.has_password')" == "true" ]] || fail "destination has_password expected true" "$DEST_READ"
echo
echo "4) Save SMTP settings with password"
SMTP_SAVE="$(api PUT "/api/v2/admin/smtp-settings" "{
  \"enabled\":true,
  \"host\":\"smtp.example.local\",
  \"port\":587,
  \"username\":\"smtp-user\",
  \"password\":\"$SMTP_PASSWORD\",
  \"from_email\":\"noreply@example.local\",
  \"from_name\":\"Link2NAS Test\",
  \"use_tls\":true,
  \"use_ssl\":false
}" "$TOKEN")"
echo "$SMTP_SAVE" | jq
assert_no_error "$SMTP_SAVE" "smtp saved"
assert_not_contains_secret "$SMTP_SAVE" "$SMTP_PASSWORD" "smtp save response"
assert_field_absent "$SMTP_SAVE" '.password' "smtp password"
assert_field_absent "$SMTP_SAVE" '.encrypted_password' "smtp encrypted_password"
[[ "$(echo "$SMTP_SAVE" | jq -r '.has_password')" == "true" ]] || fail "smtp has_password expected true" "$SMTP_SAVE"

SMTP_READ="$(api GET "/api/v2/admin/smtp-settings" "" "$TOKEN")"
echo "$SMTP_READ" | jq
assert_no_error "$SMTP_READ" "smtp read"
assert_not_contains_secret "$SMTP_READ" "$SMTP_PASSWORD" "smtp read response"
[[ "$(echo "$SMTP_READ" | jq -r '.has_password')" == "true" ]] || fail "smtp read has_password expected true" "$SMTP_READ"

echo
echo "5) Save Gotify notification config with token"
GOTIFY_SAVE="$(api POST "/api/v2/notifications/configs" "{
  \"name\":\"Secret Exposure Gotify\",
  \"channel\":\"gotify\",
  \"is_enabled\":true,
  \"config\":{
    \"server_url\":\"https://gotify.example.local\",
    \"token\":\"$GOTIFY_TOKEN\"
  }
}" "$TOKEN")"
echo "$GOTIFY_SAVE" | jq
assert_no_error "$GOTIFY_SAVE" "gotify config saved"
assert_not_contains_secret "$GOTIFY_SAVE" "$GOTIFY_TOKEN" "gotify save response"
assert_field_absent "$GOTIFY_SAVE" '.config.token' "gotify token"
[[ "$(echo "$GOTIFY_SAVE" | jq -r '.config.has_token')" == "true" ]] || fail "gotify has_token expected true" "$GOTIFY_SAVE"

GOTIFY_ID="$(echo "$GOTIFY_SAVE" | jq -r '.id')"
GOTIFY_READ="$(api GET "/api/v2/notifications/configs/$GOTIFY_ID" "" "$TOKEN")"
echo "$GOTIFY_READ" | jq
assert_no_error "$GOTIFY_READ" "gotify config read"
assert_not_contains_secret "$GOTIFY_READ" "$GOTIFY_TOKEN" "gotify read response"
assert_field_absent "$GOTIFY_READ" '.config.token' "gotify read token"

echo
echo "6) Save Webhook notification config with secret header"
WEBHOOK_SAVE="$(api POST "/api/v2/notifications/configs" "{
  \"name\":\"Secret Exposure Webhook\",
  \"channel\":\"webhook\",
  \"is_enabled\":true,
  \"config\":{
    \"url\":\"https://webhook.example.local/hook\",
    \"method\":\"POST\",
    \"headers\":{
      \"Authorization\":\"Bearer $WEBHOOK_SECRET\"
    }
  }
}" "$TOKEN")"
echo "$WEBHOOK_SAVE" | jq
assert_no_error "$WEBHOOK_SAVE" "webhook config saved"
assert_not_contains_secret "$WEBHOOK_SAVE" "$WEBHOOK_SECRET" "webhook save response"
assert_field_absent "$WEBHOOK_SAVE" '.config.headers' "webhook headers"
[[ "$(echo "$WEBHOOK_SAVE" | jq -r '.config.has_headers')" == "true" ]] || fail "webhook has_headers expected true" "$WEBHOOK_SAVE"

WEBHOOK_ID="$(echo "$WEBHOOK_SAVE" | jq -r '.id')"
WEBHOOK_READ="$(api GET "/api/v2/notifications/configs/$WEBHOOK_ID" "" "$TOKEN")"
echo "$WEBHOOK_READ" | jq
assert_no_error "$WEBHOOK_READ" "webhook config read"
assert_not_contains_secret "$WEBHOOK_READ" "$WEBHOOK_SECRET" "webhook read response"
assert_field_absent "$WEBHOOK_READ" '.config.headers' "webhook read headers"

echo
echo "7) Cleanup notification configs"
api DELETE "/api/v2/notifications/configs/$GOTIFY_ID" "" "$TOKEN" | jq
api DELETE "/api/v2/notifications/configs/$WEBHOOK_ID" "" "$TOKEN" | jq
ok "notification configs cleaned"

echo
echo "=== OK: secret exposure workflow passed ==="
