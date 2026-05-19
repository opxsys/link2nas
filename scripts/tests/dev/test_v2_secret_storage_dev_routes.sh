#!/bin/bash

set -e

BASE_URL="http://127.0.0.1:5000"
DB_PATH="data/link2nas_v2.sqlite3"

DB_BACKEND="${V2_DATABASE_BACKEND:-sqlite}"

db_query() {
  if [ "$DB_BACKEND" = "postgres" ]; then
    docker exec -i link2nas-postgres psql -U link2nas -d link2nas_v2 -t -A -c "$1"
  else
    sqlite3 "$DB_PATH" "$1"
  fi
}

RD_API_KEY="${RD_API_KEY:-fake-test-rd-secret}"
NAS_PASSWORD="TEST_NAS_PASSWORD_123456"

echo "=== CREATE USER ==="
USER_ID=$(curl -s -X POST "$BASE_URL/api/v2/dev/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"crypto-test@test.com","display_name":"Crypto Test"}' | jq -r '.id')

echo "USER_ID=$USER_ID"

echo "=== CREATE TOKEN ==="
TOKEN=$(curl -s -X POST "$BASE_URL/api/v2/dev/users/$USER_ID/tokens" \
  -H "Content-Type: application/json" \
  -d '{"label":"crypto test token"}' | jq -r '.token')

echo "TOKEN=$TOKEN"

echo "=== SAVE PROVIDER SECRET ==="
curl -s -X POST "$BASE_URL/api/v2/providers" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "{
    \"provider_name\":\"realdebrid\",
    \"api_key\":\"$RD_API_KEY\",
    \"is_default\":true
  }" | jq

echo "=== CHECK PROVIDER API RESPONSE DOES NOT LEAK SECRET ==="
PROVIDER_RESPONSE=$(curl -s "$BASE_URL/api/v2/providers/realdebrid" \
  -H "X-Api-Key: $TOKEN")

echo "$PROVIDER_RESPONSE" | jq

if echo "$PROVIDER_RESPONSE" | grep -q "$RD_API_KEY"; then
  echo "ERROR: provider API leaks api_key"
  exit 1
fi

echo "OK: provider API does not leak api_key"

echo "=== CHECK PROVIDER DB VALUE IS ENCRYPTED ==="
#DB_PROVIDER_SECRET=$(sqlite3 "$DB_PATH" "SELECT encrypted_api_key FROM provider_configs WHERE user_id='$USER_ID' AND provider_name='realdebrid';")
DB_PROVIDER_SECRET=$(db_query "SELECT encrypted_api_key FROM provider_configs WHERE user_id='$USER_ID' AND provider_name='realdebrid' LIMIT 1;")
echo "DB_PROVIDER_SECRET=$DB_PROVIDER_SECRET"

if echo "$DB_PROVIDER_SECRET" | grep -q "$RD_API_KEY"; then
  echo "ERROR: provider secret stored in cleartext"
  exit 1
fi

if ! echo "$DB_PROVIDER_SECRET" | grep -q "^enc::"; then
  echo "ERROR: provider secret is not encrypted with enc:: prefix"
  exit 1
fi

echo "OK: provider secret encrypted in DB"

echo "=== SAVE NAS SECRET ==="
NAS_CONFIG=$(jq -nc \
  --arg password "$NAS_PASSWORD" \
  '{
    synology_url: "http://nas.test.local:5000",
    username: "crypto_user",
    password: $password,
    verify_ssl: false,
    destination_base: "downloads"
  }'
)

curl -s -X POST "$BASE_URL/api/v2/destinations" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "$(jq -nc --arg config "$NAS_CONFIG" '{
    destination_name: "nas",
    config_json: $config,
    is_default: true
  }')" | jq

echo "=== CHECK DESTINATION API RESPONSE DOES NOT LEAK PASSWORD ==="
DEST_RESPONSE=$(curl -s "$BASE_URL/api/v2/destinations/nas" \
  -H "X-Api-Key: $TOKEN")

echo "$DEST_RESPONSE" | jq

if echo "$DEST_RESPONSE" | grep -q "$NAS_PASSWORD"; then
  echo "ERROR: destination API leaks NAS password"
  exit 1
fi

echo "OK: destination API does not leak password"

echo "=== CHECK NAS DB PASSWORD IS ENCRYPTED ==="
#DB_NAS_CONFIG=$(sqlite3 "$DB_PATH" "SELECT config_json FROM destination_configs WHERE user_id='$USER_ID' AND destination_name='nas';")
DB_NAS_CONFIG=$(db_query "SELECT config_json FROM destination_configs WHERE user_id='$USER_ID' AND destination_name='nas' LIMIT 1;")
DB_NAS_PASSWORD=$(echo "$DB_NAS_CONFIG" | jq -r '.password')

echo "DB_NAS_PASSWORD=$DB_NAS_PASSWORD"

if echo "$DB_NAS_PASSWORD" | grep -q "$NAS_PASSWORD"; then
  echo "ERROR: NAS password stored in cleartext"
  exit 1
fi

if ! echo "$DB_NAS_PASSWORD" | grep -q "^enc::"; then
  echo "ERROR: NAS password is not encrypted with enc:: prefix"
  exit 1
fi

echo "OK: NAS password encrypted in DB"

echo "=== TEST UPDATE WITHOUT SECRET DOES NOT ERASE EXISTING PROVIDER SECRET ==="
curl -s -X POST "$BASE_URL/api/v2/providers" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d '{
    "provider_name":"realdebrid",
    "is_default":true,
    "is_enabled":true
  }' | jq

#DB_PROVIDER_SECRET_AFTER=$(sqlite3 "$DB_PATH" "SELECT encrypted_api_key FROM provider_configs WHERE user_id='$USER_ID' AND provider_name='realdebrid';")
DB_PROVIDER_SECRET_AFTER=$(db_query "SELECT encrypted_api_key FROM provider_configs WHERE user_id='$USER_ID' AND provider_name='realdebrid' LIMIT 1;")
if [ "$DB_PROVIDER_SECRET_AFTER" != "$DB_PROVIDER_SECRET" ]; then
  echo "ERROR: provider secret changed/was erased during update without api_key"
  exit 1
fi

echo "OK: provider secret preserved on update without api_key"

echo "=== TEST UPDATE WITHOUT NAS PASSWORD DOES NOT ERASE EXISTING PASSWORD ==="
NAS_CONFIG_NO_PASSWORD=$(jq -nc \
  '{
    synology_url: "http://nas.test.local:5000",
    username: "crypto_user",
    verify_ssl: false,
    destination_base: "downloads2"
  }'
)

curl -s -X POST "$BASE_URL/api/v2/destinations" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $TOKEN" \
  -d "$(jq -nc --arg config "$NAS_CONFIG_NO_PASSWORD" '{
    destination_name: "nas",
    config_json: $config,
    is_default: true
  }')" | jq

#DB_NAS_PASSWORD_AFTER=$(sqlite3 "$DB_PATH" "SELECT config_json FROM destination_configs WHERE user_id='$USER_ID' AND destination_name='nas';" | jq -r '.password')
DB_NAS_PASSWORD_AFTER=$(db_query "SELECT config_json FROM destination_configs WHERE user_id='$USER_ID' AND destination_name='nas' LIMIT 1;" | jq -r '.password')
if [ "$DB_NAS_PASSWORD_AFTER" != "$DB_NAS_PASSWORD" ]; then
  echo "ERROR: NAS password changed/was erased during update without password"
  exit 1
fi

echo "OK: NAS password preserved on update without password"

echo "=== CRYPTO SECRETS TEST OK ==="
