#!/bin/bash

set -e

BASE_URL="http://127.0.0.1:5000"

GOOD_LOCAL_PATH="data/downloads_v2_test"
BAD_LOCAL_PATH="/root/link2nas_forbidden_test"

echo "=== CREATE USER ==="
USER_ID=$(curl -s -X POST "$BASE_URL/api/v2/dev/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"local-destination-test@test.com","display_name":"Local Destination Test"}' | jq -r '.id')

echo "USER_ID=$USER_ID"

echo "=== CREATE TOKEN ==="
TOKEN=$(curl -s -X POST "$BASE_URL/api/v2/dev/users/$USER_ID/tokens" \
  -H "Content-Type: application/json" \
  -d '{"label":"local destination test token"}' | jq -r '.token')

echo "TOKEN=$TOKEN"

echo "=== CONFIG LOCAL DESTINATION OK ==="
curl -s -X POST "$BASE_URL/api/v2/destinations" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "{
    \"destination_name\":\"local\",
    \"config_json\":\"{\\\"base_path\\\":\\\"$GOOD_LOCAL_PATH\\\"}\",
    \"is_default\":true
  }" | jq

echo "=== TEST LOCAL DESTINATION OK ==="
curl -s -X POST "$BASE_URL/api/v2/settings/destination/test" \
  -H "X-Api-Key: $TOKEN" | jq

echo "=== CONFIG LOCAL DESTINATION FORBIDDEN ==="
curl -s -X POST "$BASE_URL/api/v2/destinations" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "{
    \"destination_name\":\"local\",
    \"config_json\":\"{\\\"base_path\\\":\\\"$BAD_LOCAL_PATH\\\"}\",
    \"is_default\":true
  }" | jq

echo "=== TEST LOCAL DESTINATION FORBIDDEN ==="
curl -i -s -X POST "$BASE_URL/api/v2/settings/destination/test" \
  -H "X-Api-Key: $TOKEN"

echo
echo "=== DONE ==="
