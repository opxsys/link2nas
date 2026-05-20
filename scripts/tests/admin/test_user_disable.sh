

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

if [[ "$ADMIN_TOKEN" == "null" || -z "$ADMIN_TOKEN" ]]; then
  echo "[FAIL] Login admin impossible"
  exit 1
fi

echo "=== CREATE USER ==="
USER_JSON=$(curl -s -X POST "$BASE_URL/admin/users" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $ADMIN_TOKEN" \
  -d "{\"email\":\"$USER_EMAIL\",\"display_name\":\"Disable Test\",\"password\":\"$USER_PASS\",\"is_super_admin\":false}")
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

if [[ "$USER_TOKEN" == "null" || -z "$USER_TOKEN" ]]; then
  echo "[FAIL] Login user impossible"
  exit 1
fi

echo "=== TEST /me AVANT DISABLE ==="
curl -i "$BASE_URL/me" \
  -H "X-Api-Key: $USER_TOKEN"

echo
echo "=== TEST JOBS AVANT DISABLE ==="
curl -i "$BASE_URL/jobs" \
  -H "X-Api-Key: $USER_TOKEN"

echo
echo "=== DISABLE USER ==="
curl -i -X POST "$BASE_URL/admin/users/$USER_ID/disable" \
  -H "X-Api-Key: $ADMIN_TOKEN"

echo
echo "=== TEST /me APRES DISABLE ==="
curl -i "$BASE_URL/me" \
  -H "X-Api-Key: $USER_TOKEN"

echo
echo "=== TEST JOBS APRES DISABLE ==="
curl -i "$BASE_URL/jobs" \
  -H "X-Api-Key: $USER_TOKEN"

echo
echo "=== CLEANUP: DELETE USER ==="
curl -s -X DELETE "$BASE_URL/admin/users/$USER_ID" \
  -H "X-Api-Key: $ADMIN_TOKEN" | jq || true
