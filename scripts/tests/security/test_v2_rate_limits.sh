#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"

echo "=== Link2NAS V2 rate limits test ==="
echo "Backend=${V2_DATABASE_BACKEND:-sqlite}"
echo "BASE_URL=$BASE_URL"

assert_http() {
  local expected="$1"
  local actual="$2"
  local label="$3"

  if [[ "$actual" == "$expected" ]]; then
    echo "[OK] $label => HTTP $actual"
  else
    echo "[KO] $label expected HTTP $expected got HTTP $actual"
    exit 1
  fi
}

echo
echo "1) Login brute force"
for i in 1 2; do
  curl -s -o /tmp/l2n_rate_login_$i.json -w "%{http_code}"     -X POST "$BASE_URL/api/v2/auth/login"     -H "Content-Type: application/json"     -d '{"email":"rate-login@test.local","password":"wrong"}'
  echo
done

CODE="$(curl -s -o /tmp/l2n_rate_login_3.json -w "%{http_code}"   -X POST "$BASE_URL/api/v2/auth/login"   -H "Content-Type: application/json"   -d '{"email":"rate-login@test.local","password":"wrong"}')"
cat /tmp/l2n_rate_login_3.json | jq
assert_http 429 "$CODE" "login rate limit"

echo
echo "2) Magic-login spam"
for i in 1 2; do
  curl -s -o /tmp/l2n_rate_magic_$i.json -w "%{http_code}"     -X POST "$BASE_URL/api/v2/public/magic-login/request"     -H "Content-Type: application/json"     -d '{"email":"rate-magic@test.local"}'
  echo
done

CODE="$(curl -s -o /tmp/l2n_rate_magic_3.json -w "%{http_code}"   -X POST "$BASE_URL/api/v2/public/magic-login/request"   -H "Content-Type: application/json"   -d '{"email":"rate-magic@test.local"}')"
cat /tmp/l2n_rate_magic_3.json | jq
assert_http 429 "$CODE" "magic-login request rate limit"

echo
echo "3) Token status scan"
for i in 1 2; do
  curl -s -o /tmp/l2n_rate_token_$i.json -w "%{http_code}"     "$BASE_URL/api/v2/public/tokens/invalid-token-$i/status"
  echo
done

CODE="$(curl -s -o /tmp/l2n_rate_token_3.json -w "%{http_code}"   "$BASE_URL/api/v2/public/tokens/invalid-token-3/status")"
cat /tmp/l2n_rate_token_3.json | jq
assert_http 429 "$CODE" "token status rate limit"

echo
echo "4) Public token confirmation abuse"
for i in 1 2; do
  curl -s -o /tmp/l2n_rate_confirm_$i.json -w "%{http_code}"     -X POST "$BASE_URL/api/v2/public/password-reset/confirm"     -H "Content-Type: application/json"     -d '{"token":"invalid-token","password":"Whatever123!"}'
  echo
done

CODE="$(curl -s -o /tmp/l2n_rate_confirm_3.json -w "%{http_code}"   -X POST "$BASE_URL/api/v2/public/password-reset/confirm"   -H "Content-Type: application/json"   -d '{"token":"invalid-token","password":"Whatever123!"}')"
cat /tmp/l2n_rate_confirm_3.json | jq
assert_http 429 "$CODE" "public token confirm rate limit"

echo
echo "=== OK: rate limits workflow passed ==="
