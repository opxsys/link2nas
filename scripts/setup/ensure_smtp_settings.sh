#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

SMTP_ENABLED="${SMTP_ENABLED:-true}"
SMTP_HOST="${SMTP_HOST:-smtp.example.local}"
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_USERNAME="${SMTP_USERNAME:?SMTP_USERNAME is required}"
SMTP_PASSWORD="${SMTP_PASSWORD:?SMTP_PASSWORD is required}"
SMTP_FROM_EMAIL="${SMTP_FROM_EMAIL:-noreply@example.local}"
SMTP_FROM_NAME="${SMTP_FROM_NAME:-Link2NAS-dev}"
SMTP_USE_TLS="${SMTP_USE_TLS:-false}"
SMTP_USE_SSL="${SMTP_USE_SSL:-false}"

echo "=== Ensure SMTP settings ==="
echo "BASE_URL=$BASE_URL"
echo "SMTP_HOST=$SMTP_HOST"
echo "SMTP_PORT=$SMTP_PORT"
echo "SMTP_FROM_EMAIL=$SMTP_FROM_EMAIL"

login_payload="$(jq -n \
  --arg email "$ADMIN_EMAIL" \
  --arg password "$ADMIN_PASSWORD" \
  '{email:$email,password:$password}')"

login_response="$(curl -sS -X POST "$BASE_URL/api/v2/auth/login" \
  -H "Content-Type: application/json" \
  -d "$login_payload")"

echo "$login_response" | jq .

token="$(echo "$login_response" | jq -r '.token // empty')"

if [ -z "$token" ]; then
  echo "[FAIL] admin login failed"
  exit 1
fi

echo "[OK] admin token received"

smtp_payload="$(jq -n \
  --argjson enabled "$SMTP_ENABLED" \
  --arg host "$SMTP_HOST" \
  --argjson port "$SMTP_PORT" \
  --arg username "$SMTP_USERNAME" \
  --arg password "$SMTP_PASSWORD" \
  --arg from_email "$SMTP_FROM_EMAIL" \
  --arg from_name "$SMTP_FROM_NAME" \
  --argjson use_tls "$SMTP_USE_TLS" \
  --argjson use_ssl "$SMTP_USE_SSL" \
  '{
    enabled: $enabled,
    host: $host,
    port: $port,
    username: $username,
    password: $password,
    from_email: $from_email,
    from_name: $from_name,
    use_tls: $use_tls,
    use_ssl: $use_ssl
  }')"

smtp_response="$(curl -sS -X PUT "$BASE_URL/api/v2/admin/smtp-settings" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $token" \
  -d "$smtp_payload")"

echo "$smtp_response" | jq .

if echo "$smtp_response" | jq -e '.error' >/dev/null; then
  echo "[FAIL] SMTP settings save failed"
  exit 1
fi

echo "[OK] SMTP settings saved"

# Optional: enable this only when a real SMTP server is reachable.
if [ "${SMTP_RUN_TEST:-false}" = "true" ]; then
  echo "=== SMTP send test ==="

  test_response="$(curl -sS -X POST "$BASE_URL/api/v2/admin/smtp-settings/test" \
    -H "X-Api-Key: $token")"

  echo "$test_response" | jq .

  if ! echo "$test_response" | jq -e '.ok == true' >/dev/null; then
    echo "[FAIL] SMTP test failed"
    exit 1
  fi

  echo "[OK] SMTP test email sent"
fi
