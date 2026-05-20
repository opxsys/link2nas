#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:5000/api/v2"

ADMIN_EMAIL="admin@link2nas.local"
ADMIN_PASS="change-me-strong-password"

USER_EMAIL="expire-token-test@local"
USER_PASS="${USER_PASS:-TestPassword123!}"

POSTGRES_CONTAINER="link2nas-postgres"
POSTGRES_USER="link2nas"
POSTGRES_DB="link2nas_v2"

FUTURE_EXPIRATION="2099-01-01T00:00:00+00:00"
PAST_EXPIRATION="2000-01-01T00:00:00+00:00"

echo "=== LOGIN ADMIN ==="
ADMIN_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.token')

if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
  echo "[FAIL] Login admin impossible"
  exit 1
fi

echo "=== CREATE USER WITH FUTURE EXPIRATION ==="
USER_JSON=$(curl -s -X POST "$BASE_URL/admin/users" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $ADMIN_TOKEN" \
  -d "{
    \"email\":\"$USER_EMAIL\",
    \"display_name\":\"Expire Token Test\",
    \"password\":\"$USER_PASS\",
    \"is_super_admin\":false,
    \"account_expires_at\":\"$FUTURE_EXPIRATION\"
  }")

echo "$USER_JSON" | jq
USER_ID=$(echo "$USER_JSON" | jq -r '.id')

if [[ -z "$USER_ID" || "$USER_ID" == "null" ]]; then
  echo "[FAIL] Création user impossible"
  exit 1
fi

echo "USER_ID=$USER_ID"

echo "=== LOGIN USER BEFORE EXPIRATION ==="
USER_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASS\"}" | jq -r '.token')

if [[ -z "$USER_TOKEN" || "$USER_TOKEN" == "null" ]]; then
  echo "[FAIL] Login user impossible avant expiration"
  exit 1
fi

echo "=== /me BEFORE EXPIRATION SHOULD BE 200 ==="
HTTP_CODE=$(curl -s -o /tmp/l2n_exp_before.json -w "%{http_code}" \
  "$BASE_URL/me" \
  -H "X-Api-Key: $USER_TOKEN")

cat /tmp/l2n_exp_before.json | jq
echo "HTTP_CODE=$HTTP_CODE"

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "[FAIL] /me avant expiration attendu 200"
  exit 1
fi

echo "=== FORCE ACCOUNT EXPIRATION IN POSTGRES ==="
docker exec -i "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<SQL
UPDATE users
SET account_expires_at = '$PAST_EXPIRATION',
    updated_at = now()
WHERE id = '$USER_ID';
SQL

echo "=== /me AFTER EXPIRATION SHOULD BE 401 Account expired ==="
HTTP_CODE=$(curl -s -o /tmp/l2n_exp_after.json -w "%{http_code}" \
  "$BASE_URL/me" \
  -H "X-Api-Key: $USER_TOKEN")

cat /tmp/l2n_exp_after.json | jq
echo "HTTP_CODE=$HTTP_CODE"

ERROR_MSG=$(jq -r '.error // empty' /tmp/l2n_exp_after.json)

if [[ "$HTTP_CODE" != "401" || "$ERROR_MSG" != "Account expired" ]]; then
  echo "[FAIL] /me après expiration attendu 401 + Account expired"
  exit 1
fi

echo "=== /jobs AFTER EXPIRATION SHOULD BE 401 Account expired ==="
HTTP_CODE=$(curl -s -o /tmp/l2n_exp_jobs_after.json -w "%{http_code}" \
  "$BASE_URL/jobs" \
  -H "X-Api-Key: $USER_TOKEN")

cat /tmp/l2n_exp_jobs_after.json | jq
echo "HTTP_CODE=$HTTP_CODE"

ERROR_MSG=$(jq -r '.error // empty' /tmp/l2n_exp_jobs_after.json)

if [[ "$HTTP_CODE" != "401" || "$ERROR_MSG" != "Account expired" ]]; then
  echo "[FAIL] /jobs après expiration attendu 401 + Account expired"
  exit 1
fi

echo
echo "[OK] Existing token rejected after account expiration."
