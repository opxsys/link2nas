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
    cat "${4:-/dev/null}" 2>/dev/null || true
    exit 1
  fi
}

post_json() {
  local url="$1"
  local body="$2"
  local out="$3"

  curl -s -o "$out" -w "%{http_code}" \
    -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "$body"
}

get_url() {
  local url="$1"
  local out="$2"

  curl -s -o "$out" -w "%{http_code}" "$url"
}

echo
echo "0) Reset anti-abuse counters before rate-limit test"

ADMIN_TOKEN="${ADMIN_API_KEY:-${TOKEN:-}}"

if [[ -n "$ADMIN_TOKEN" ]]; then
  CODE="$(curl -s -o /tmp/l2n_rate_reset.json -w "%{http_code}" \
    -X POST "$BASE_URL/api/v2/admin/security/anti-abuse/reset" \
    -H "X-Api-Key: $ADMIN_TOKEN")"

  cat /tmp/l2n_rate_reset.json | jq || cat /tmp/l2n_rate_reset.json

  if [[ "$CODE" != "200" ]]; then
    echo "[KO] anti-abuse reset expected HTTP 200 got HTTP $CODE"
    exit 1
  fi

  echo "[OK] anti-abuse counters reset"
else
  echo "[WARN] ADMIN_API_KEY/TOKEN missing; rate-limit test may be polluted by previous runs"
fi

echo
echo "1) Login brute force"
for i in $(seq 1 10); do
  CODE="$(post_json "$BASE_URL/api/v2/auth/login" \
    '{"email":"rate-login@test.local","password":"wrong"}' \
    "/tmp/l2n_rate_login_$i.json")"
  assert_http 401 "$CODE" "login attempt $i before limit" "/tmp/l2n_rate_login_$i.json"
done

CODE="$(post_json "$BASE_URL/api/v2/auth/login" \
  '{"email":"rate-login@test.local","password":"wrong"}' \
  "/tmp/l2n_rate_login_11.json")"
cat /tmp/l2n_rate_login_11.json | jq
assert_http 429 "$CODE" "login rate limit" "/tmp/l2n_rate_login_11.json"

echo
echo "2) Magic-login spam"
for i in $(seq 1 5); do
  CODE="$(post_json "$BASE_URL/api/v2/public/magic-login/request" \
    '{"email":"rate-magic@test.local"}' \
    "/tmp/l2n_rate_magic_$i.json")"
  assert_http 200 "$CODE" "magic-login request $i before limit" "/tmp/l2n_rate_magic_$i.json"
done

CODE="$(post_json "$BASE_URL/api/v2/public/magic-login/request" \
  '{"email":"rate-magic@test.local"}' \
  "/tmp/l2n_rate_magic_6.json")"
cat /tmp/l2n_rate_magic_6.json | jq
assert_http 429 "$CODE" "magic-login request rate limit" "/tmp/l2n_rate_magic_6.json"

echo
echo "3) Token status scan"
for i in $(seq 1 60); do
  CODE="$(get_url "$BASE_URL/api/v2/public/tokens/invalid-token-$i/status" \
    "/tmp/l2n_rate_token_$i.json")"

  # Un token invalide peut répondre 404/400 selon ton implémentation.
  if [[ "$CODE" != "400" && "$CODE" != "404" ]]; then
    echo "[KO] token status attempt $i expected HTTP 400/404 before limit got HTTP $CODE"
    cat "/tmp/l2n_rate_token_$i.json"
    exit 1
  fi
done

CODE="$(get_url "$BASE_URL/api/v2/public/tokens/invalid-token-61/status" \
  "/tmp/l2n_rate_token_61.json")"
cat /tmp/l2n_rate_token_61.json | jq
assert_http 429 "$CODE" "token status rate limit" "/tmp/l2n_rate_token_61.json"

echo
echo "4) Public token confirmation abuse"
for i in $(seq 1 20); do
  CODE="$(post_json "$BASE_URL/api/v2/public/password-reset/confirm" \
    '{"token":"invalid-token","password":"Whatever123!"}' \
    "/tmp/l2n_rate_confirm_$i.json")"

  # Selon la validation exacte : 400, 404 ou 401 sont acceptables avant limite.
  if [[ "$CODE" != "400" && "$CODE" != "401" && "$CODE" != "404" ]]; then
    echo "[KO] token confirm attempt $i expected HTTP 400/401/404 before limit got HTTP $CODE"
    cat "/tmp/l2n_rate_confirm_$i.json"
    exit 1
  fi
done

CODE="$(post_json "$BASE_URL/api/v2/public/password-reset/confirm" \
  '{"token":"invalid-token","password":"Whatever123!"}' \
  "/tmp/l2n_rate_confirm_21.json")"
cat /tmp/l2n_rate_confirm_21.json | jq
assert_http 429 "$CODE" "public token confirm rate limit" "/tmp/l2n_rate_confirm_21.json"

echo
echo "=== OK: rate limits workflow passed ==="
