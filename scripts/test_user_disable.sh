

#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:5000/api/v2"

ADMIN_EMAIL="admin@link2nas.local"
ADMIN_PASS="change-me-strong-password"

USER_EMAIL="${USER_EMAIL:-user@test.local}"
USER_PASS="${USER_PASS:?USER_PASS is required}"

echo "=== LOGIN ADMIN ==="
ADMIN_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.token')

if [[ "$ADMIN_TOKEN" == "null" || -z "$ADMIN_TOKEN" ]]; then
  echo "[FAIL] Login admin impossible"
  exit 1
fi

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
echo "=== RECUP ID USER ==="
USER_ID=$(curl -s "$BASE_URL/admin/users" \
  -H "X-Api-Key: $ADMIN_TOKEN" | jq -r ".[] | select(.email==\"$USER_EMAIL\") | .id")

if [[ "$USER_ID" == "null" || -z "$USER_ID" ]]; then
  echo "[FAIL] User introuvable"
  exit 1
fi

echo "USER_ID=$USER_ID"

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