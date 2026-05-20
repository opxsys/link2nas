#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:5000/api/v2"

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@link2nas.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${ADMIN_PASS:-change-me-strong-password}}"

USER_EMAIL="${USER_EMAIL:-disable-user-$(date +%s)-$RANDOM@test.local}"
USER_PASS="${USER_PASS:-TestPassword123!}"

echo "=== LOGIN ADMIN ==="
ADMIN_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r '.token')

if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
  echo "[FAIL] Login admin impossible"
  exit 1
fi

echo "=== CREATE USER ==="
USER_JSON=$(curl -s -X POST "$BASE_URL/admin/users" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $ADMIN_TOKEN" \
  -d "{\"email\":\"$USER_EMAIL\",\"display_name\":\"Disable Connected Test\",\"password\":\"$USER_PASS\",\"is_super_admin\":false}")
USER_ID=$(echo "$USER_JSON" | jq -r '.id')

if [[ -z "$USER_ID" || "$USER_ID" == "null" ]]; then
  echo "[FAIL] User creation failed"
  echo "$USER_JSON" | jq
  exit 1
fi

echo "USER_ID=$USER_ID"

echo "=== LOGIN USER ==="
USER_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASS\"}" | jq -r '.token')

if [[ -z "$USER_TOKEN" || "$USER_TOKEN" == "null" ]]; then
  echo "[FAIL] Login user impossible"
  exit 1
fi

echo
echo "=== BEFORE DISABLE: /me should be 200 ==="
HTTP_CODE=$(curl -s -o /tmp/l2n_me_before.json -w "%{http_code}" \
  "$BASE_URL/me" \
  -H "X-Api-Key: $USER_TOKEN")

cat /tmp/l2n_me_before.json | jq || cat /tmp/l2n_me_before.json
echo "HTTP_CODE=$HTTP_CODE"

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "[FAIL] /me avant disable attendu 200"
  exit 1
fi

echo
echo "=== DISABLE USER WHILE TOKEN IS STILL ACTIVE ==="
curl -s -X POST "$BASE_URL/admin/users/$USER_ID/disable" \
  -H "X-Api-Key: $ADMIN_TOKEN" | jq

echo
echo "=== AFTER DISABLE: /me should be 401 User disabled ==="
HTTP_CODE=$(curl -s -o /tmp/l2n_me_after.json -w "%{http_code}" \
  "$BASE_URL/me" \
  -H "X-Api-Key: $USER_TOKEN")

cat /tmp/l2n_me_after.json | jq || cat /tmp/l2n_me_after.json
echo "HTTP_CODE=$HTTP_CODE"

ERROR_MSG=$(jq -r '.error // empty' /tmp/l2n_me_after.json)

if [[ "$HTTP_CODE" != "401" || "$ERROR_MSG" != "User disabled" ]]; then
  echo "[FAIL] /me après disable attendu 401 + User disabled"
  exit 1
fi

echo
echo "=== AFTER DISABLE: /jobs should be 401 User disabled ==="
HTTP_CODE=$(curl -s -o /tmp/l2n_jobs_after.json -w "%{http_code}" \
  "$BASE_URL/jobs" \
  -H "X-Api-Key: $USER_TOKEN")

cat /tmp/l2n_jobs_after.json | jq || cat /tmp/l2n_jobs_after.json
echo "HTTP_CODE=$HTTP_CODE"

ERROR_MSG=$(jq -r '.error // empty' /tmp/l2n_jobs_after.json)

if [[ "$HTTP_CODE" != "401" || "$ERROR_MSG" != "User disabled" ]]; then
  echo "[FAIL] /jobs après disable attendu 401 + User disabled"
  exit 1
fi

echo
echo "=== CLEANUP: DELETE USER ==="
curl -s -X DELETE "$BASE_URL/admin/users/$USER_ID" \
  -H "X-Api-Key: $ADMIN_TOKEN" | jq || true

echo
echo "[OK] Connected disabled user is rejected on protected endpoints."
