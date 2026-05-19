#!/bin/bash

set -e

BASE_URL="http://127.0.0.1:5000"
RD_API_KEY="${RD_API_KEY:?RD_API_KEY is required}"

echo "=== CREATE USER ==="
USER_ID=$(curl -s -X POST "$BASE_URL/api/v2/dev/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"provider-expiration@test.com","display_name":"Provider Expiration Test"}' | jq -r '.id')

echo "USER_ID=$USER_ID"

echo "=== CREATE TOKEN ==="
TOKEN=$(curl -s -X POST "$BASE_URL/api/v2/dev/users/$USER_ID/tokens" \
  -H "Content-Type: application/json" \
  -d '{"label":"provider expiration test token"}' | jq -r '.token')

echo "TOKEN=$TOKEN"

echo "=== CONFIG PROVIDER ==="
curl -s -X POST "$BASE_URL/api/v2/providers" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "{
    \"provider_name\":\"realdebrid\",
    \"encrypted_api_key\":\"$RD_API_KEY\",
    \"is_default\":true
  }" | jq

echo "=== PROVIDERS BEFORE TEST ==="
curl -s -H "X-Api-Key: $TOKEN" \
  "$BASE_URL/api/v2/providers" | jq

echo "=== TEST PROVIDER ==="
curl -s -X POST \
  -H "X-Api-Key: $TOKEN" \
  "$BASE_URL/api/v2/settings/provider/test" | jq

echo "=== PROVIDERS AFTER TEST ==="
curl -s -H "X-Api-Key: $TOKEN" \
  "$BASE_URL/api/v2/providers" | jq

echo "=== DB CHECK ==="
sqlite3 data/link2nas_v2.sqlite3 \
"SELECT provider_name, account_expires_at FROM provider_configs WHERE user_id = '$USER_ID';"

echo "=== DONE ==="
