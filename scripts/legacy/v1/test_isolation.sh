#!/bin/bash

set -e

BASE_URL="http://127.0.0.1:5000"

MAGNET_LINK="magnet:?xt=urn:btih:e15050d9b20cd622212d3aecd253790bf9602732"
RD_API_KEY="${RD_API_KEY:?RD_API_KEY is required}"

echo "=== CREATE USER A ==="
USER_A_ID=$(curl -s -X POST "$BASE_URL/api/v2/dev/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"isolation-a@test.com","display_name":"Isolation A"}' | jq -r '.id')

TOKEN_A=$(curl -s -X POST "$BASE_URL/api/v2/dev/users/$USER_A_ID/tokens" \
  -H "Content-Type: application/json" \
  -d '{"label":"isolation token A"}' | jq -r '.token')

echo "USER_A_ID=$USER_A_ID"
echo "TOKEN_A=$TOKEN_A"

echo "=== CREATE USER B ==="
USER_B_ID=$(curl -s -X POST "$BASE_URL/api/v2/dev/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"isolation-b@test.com","display_name":"Isolation B"}' | jq -r '.id')

TOKEN_B=$(curl -s -X POST "$BASE_URL/api/v2/dev/users/$USER_B_ID/tokens" \
  -H "Content-Type: application/json" \
  -d '{"label":"isolation token B"}' | jq -r '.token')

echo "USER_B_ID=$USER_B_ID"
echo "TOKEN_B=$TOKEN_B"

echo "=== CONFIG PROVIDER A ONLY ==="
curl -s -X POST "$BASE_URL/api/v2/providers" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN_A" \
  -d "{
    \"provider_name\":\"realdebrid\",
    \"api_key\":\"$RD_API_KEY\",
    \"is_default\":true
  }" | jq

echo "=== CONFIG DESTINATION A ONLY ==="
curl -s -X POST "$BASE_URL/api/v2/destinations" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN_A" \
  -d '{
    "destination_name":"links_only",
    "config_json":"{}",
    "is_default":true
  }' | jq

echo "=== CREATE JOB A ==="
JOB_A_ID=$(curl -s -X POST "$BASE_URL/api/v2/jobs" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN_A" \
  -d "{
    \"source_type\":\"magnet\",
    \"source_value\":\"$MAGNET_LINK\",
    \"provider_name\":\"realdebrid\"
  }" | jq -r '.id')

echo "JOB_A_ID=$JOB_A_ID"

echo "=== CREATE JOB B ==="
JOB_B_ID=$(curl -s -X POST "$BASE_URL/api/v2/jobs" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN_B" \
  -d "{
    \"source_type\":\"magnet\",
    \"source_value\":\"$MAGNET_LINK\",
    \"provider_name\":\"realdebrid\"
  }" | jq -r '.id')

echo "JOB_B_ID=$JOB_B_ID"

echo
echo "========================================"
echo "TEST 1: USER A LISTS JOBS"
echo "Expected: sees JOB_A only"
echo "========================================"
curl -s -H "X-Api-Key: $TOKEN_A" \
  "$BASE_URL/api/v2/jobs" | jq

echo
echo "========================================"
echo "TEST 2: USER B LISTS JOBS"
echo "Expected: sees JOB_B only"
echo "========================================"
curl -s -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/jobs" | jq

echo
echo "========================================"
echo "TEST 3: USER B GETS JOB A"
echo "Expected: 404 Not found"
echo "========================================"
curl -i -s -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/jobs/$JOB_A_ID"

echo
echo
echo "========================================"
echo "TEST 4: USER A GETS JOB B"
echo "Expected: 404 Not found"
echo "========================================"
curl -i -s -H "X-Api-Key: $TOKEN_A" \
  "$BASE_URL/api/v2/jobs/$JOB_B_ID"

echo
echo
echo "========================================"
echo "TEST 5: USER B STARTS JOB A"
echo "Expected: 404 Not found OR safe error, never starts"
echo "========================================"
curl -i -s -X POST \
  -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/jobs/$JOB_A_ID/start"

echo
echo
echo "========================================"
echo "TEST 6: USER A STARTS JOB B"
echo "Expected: 404 Not found OR safe error, never starts"
echo "========================================"
curl -i -s -X POST \
  -H "X-Api-Key: $TOKEN_A" \
  "$BASE_URL/api/v2/jobs/$JOB_B_ID/start"

echo
echo
echo "========================================"
echo "TEST 7: USER B READS PROVIDERS"
echo "Expected: []"
echo "========================================"
curl -s -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/providers" | jq

echo
echo "========================================"
echo "TEST 8: USER B READS REALDEBRID CONFIG"
echo "Expected: 404 Not found"
echo "========================================"
curl -i -s -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/providers/realdebrid"

echo
echo
echo "========================================"
echo "TEST 9: USER B READS DESTINATIONS"
echo "Expected: []"
echo "========================================"
curl -s -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/destinations" | jq

echo
echo "========================================"
echo "TEST 10: USER B READS LINKS_ONLY DESTINATION"
echo "Expected: 404 Not found"
echo "========================================"
curl -i -s -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/destinations/links_only"

echo
echo
echo "========================================"
echo "TEST 11: USER B STARTS OWN JOB WITHOUT PROVIDER"
echo "Expected: Provider config not found"
echo "========================================"
curl -i -s -X POST \
  -H "X-Api-Key: $TOKEN_B" \
  "$BASE_URL/api/v2/jobs/$JOB_B_ID/start"

echo
echo
echo "=== DONE ISOLATION TEST ==="
