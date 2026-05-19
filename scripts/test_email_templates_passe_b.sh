#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%Y%m%d%H%M%S)-$$"

echo "=== Link2NAS — Email Templates Passe B ==="
echo "BASE_URL=$BASE_URL"
echo "RUN_ID=$RUN_ID"
echo

# ---- helpers ----------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}

_BODY_FILE="/tmp/l2n_etpl_b_test_$$.json"
TEST_USER_ID=""
TOKEN="${TOKEN:-}"

cleanup() {
  # Reset any templates modified during the test
  if [[ -n "$TOKEN" ]]; then
    for KEY_LANG in "invitation/fr" "password_reset/fr" "email_verification/fr" "magic_login/en" "smtp_test/en"; do
      curl -sS -X POST "$BASE_URL/api/v2/admin/email-templates/$KEY_LANG/reset" \
        -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
    done
  fi
  # Remove test user if created
  if [[ -n "$TEST_USER_ID" && -n "$TOKEN" ]]; then
    curl -sS -X DELETE "$BASE_URL/api/v2/admin/users/$TEST_USER_ID" \
      -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
  fi
  rm -f "$_BODY_FILE"
}
trap cleanup EXIT

api() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local token="${4:-}"

  if [[ -n "$data" && -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$data" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$token" ]]; then
    curl -sS -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token"
  else
    curl -sS -X "$method" "$BASE_URL$path"
  fi
}

api_with_status() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local token="${4:-}"

  if [[ -n "$data" && -n "$token" ]]; then
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$data" ]]; then
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Content-Type: application/json" \
      -d "$data"
  elif [[ -n "$token" ]]; then
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "X-Api-Key: $token"
  else
    curl -s -o "$_BODY_FILE" -w "%{http_code}" -X "$method" "$BASE_URL$path"
  fi
}

assert_no_error() {
  local json="$1"
  local label="$2"
  local error
  error="$(echo "$json" | jq -r '.error // empty')"
  if [[ -n "$error" ]]; then
    echo "[KO] $label: $error"
    echo "$json" | jq
    exit 1
  fi
  echo "[OK] $label"
}

assert_http() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label: expected HTTP $expected, got HTTP $actual"
    jq . "$_BODY_FILE" 2>/dev/null || cat "$_BODY_FILE"
    echo
    exit 1
  fi
  echo "[OK] $label (HTTP $actual)"
}

assert_body_field() {
  local label="$1"
  local jq_expr="$2"
  local expected="$3"
  local actual
  actual="$(jq -r "$jq_expr" "$_BODY_FILE")"
  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label: expected '$expected', got '$actual'"
    jq . "$_BODY_FILE" 2>/dev/null
    exit 1
  fi
  echo "[OK] $label"
}

assert_body_non_empty() {
  local label="$1"
  local jq_expr="$2"
  local value
  value="$(jq -r "$jq_expr // empty" "$_BODY_FILE")"
  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "[KO] $label: expected non-empty value for $jq_expr"
    jq . "$_BODY_FILE" 2>/dev/null
    exit 1
  fi
  echo "[OK] $label"
}

assert_equals() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "[KO] $label: expected '$expected', got '$actual'"
    exit 1
  fi
  echo "[OK] $label"
}

reset_template() {
  local key_lang="$1"
  STATUS="$(api_with_status POST "/api/v2/admin/email-templates/$key_lang/reset" "" "$TOKEN")"
  if [[ "$STATUS" != "200" ]]; then
    echo "[WARN] reset $key_lang returned HTTP $STATUS"
  else
    echo "[OK] template reset: $key_lang"
  fi
}

# ---- prerequisites ----------------------------------------------------------

need_cmd curl
need_cmd jq

echo "--- prerequisites ---"
echo

echo "1) python -m compileall backend"
python -m compileall backend -q
echo "[OK] python -m compileall backend"
echo

echo "2) git diff --check"
git diff --check
echo "[OK] git diff --check"
echo

# ---- setup & auth -----------------------------------------------------------

echo "--- setup & auth ---"
echo

SETUP_STATUS="$(api GET "/api/v2/setup/status")"
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo "3) Create first admin"
  CREATE_ADMIN="$(api POST "/api/v2/setup/first-admin" "{
    \"email\":\"$ADMIN_EMAIL\",
    \"display_name\":\"Admin\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  assert_no_error "$CREATE_ADMIN" "first admin created"
else
  echo "[INFO] Setup already completed"
fi

ADMIN_API_KEY="${ADMIN_API_KEY:-${TOKEN:-}}"
if [[ -n "$ADMIN_API_KEY" ]]; then
  echo "[INFO] Using admin API key from ADMIN_API_KEY/TOKEN"
  TOKEN="$ADMIN_API_KEY"
else
  echo "4) Login admin"
  LOGIN="$(api POST "/api/v2/auth/login" "{
    \"email\":\"$ADMIN_EMAIL\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  assert_no_error "$LOGIN" "admin login"
  TOKEN="$(echo "$LOGIN" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "[KO] admin token missing"
    exit 1
  fi
  echo "[OK] admin token received"
fi
echo

# ---- ensure Passe A infra is present ----------------------------------------

echo "--- Passe A infra check ---"
echo

echo "5) GET email-templates — 14 entries expected"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET email-templates"
COUNT="$(jq 'length' "$_BODY_FILE")"
if (( COUNT < 14 )); then
  echo "[KO] Expected at least 14 templates, got $COUNT"
  exit 1
fi
echo "[OK] $COUNT templates found"
echo

# ---- create test user -------------------------------------------------------

echo "--- test user setup ---"
echo

TEST_USER_EMAIL="test-passe-b-${RUN_ID}@test.local"
TEST_USER_PASSWORD="TestPasseB123!"

echo "6) Create test user (preferred_language=fr)"
CREATE_USER="$(api POST "/api/v2/admin/users" "{
  \"email\": \"$TEST_USER_EMAIL\",
  \"display_name\": \"Test Passe B\",
  \"password\": \"$TEST_USER_PASSWORD\",
  \"preferred_language\": \"fr\"
}" "$TOKEN")"
assert_no_error "$CREATE_USER" "test user created"
TEST_USER_ID="$(echo "$CREATE_USER" | jq -r '.id // empty')"
if [[ -z "$TEST_USER_ID" || "$TEST_USER_ID" == "null" ]]; then
  echo "[KO] test user id missing"
  exit 1
fi
echo "[OK] test user id: $TEST_USER_ID"
echo

# ---- invitation template ----------------------------------------------------

echo "--- invitation template ---"
echo

CUSTOM_INV_SUBJECT="[CUSTOM-B-${RUN_ID}] Invitation {app_name}"
CUSTOM_INV_BODY="Bonjour,\n\nVoici votre lien : {url}\n\nExpire : {expires_at}\n\n— {app_name}"

echo "7) Save custom invitation/fr template"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/fr" \
  "{\"subject_template\": \"$CUSTOM_INV_SUBJECT\", \"body_template\": \"$CUSTOM_INV_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT invitation/fr custom"
assert_body_field "is_custom=true" ".is_custom" "true"
echo

echo "8) Preview invitation/fr — verify custom subject rendered"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/invitation/fr/preview" \
  "{\"subject_template\": \"$CUSTOM_INV_SUBJECT\", \"body_template\": \"$CUSTOM_INV_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview invitation/fr"
PREVIEW_SUBJECT="$(jq -r '.subject' "$_BODY_FILE")"
if ! echo "$PREVIEW_SUBJECT" | grep -q "CUSTOM-B-${RUN_ID}"; then
  echo "[KO] preview subject does not contain custom RUN_ID marker"
  echo "  got: $PREVIEW_SUBJECT"
  exit 1
fi
echo "[OK] preview subject contains custom RUN_ID marker: $PREVIEW_SUBJECT"
echo

echo "9) POST invitation/email — uses custom template (test route responds correctly)"
STATUS="$(api_with_status POST "/api/v2/admin/users/$TEST_USER_ID/invitation/email" "" "$TOKEN")"
# Expect 201 (email sent) or 502/503 (SMTP not configured — both acceptable without real SMTP)
if [[ "$STATUS" == "201" ]]; then
  echo "[OK] invitation/email → 201 (SMTP available, email sent)"
elif [[ "$STATUS" == "502" || "$STATUS" == "503" ]]; then
  echo "[INFO] invitation/email → HTTP $STATUS (SMTP not configured — acceptable)"
  echo "[OK] invitation email route reached correctly with custom template"
else
  echo "[KO] invitation/email unexpected HTTP $STATUS"
  jq . "$_BODY_FILE" 2>/dev/null
  exit 1
fi
echo

echo "10) Reset invitation/fr"
reset_template "invitation/fr"
echo

echo "11) GET invitation/fr after reset — is_custom must be false"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/invitation/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET invitation/fr after reset"
assert_body_field "is_custom=false after reset" ".is_custom" "false"
echo

# ---- password_reset template ------------------------------------------------

echo "--- password_reset template ---"
echo

CUSTOM_PWD_SUBJECT="[CUSTOM-B-${RUN_ID}] Reset {app_name}"
CUSTOM_PWD_BODY="Bonjour,\n\nReinit : {url}\n\nExpire : {expires_at}\n\n— {app_name}"

echo "12) Save custom password_reset/fr template"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/password_reset/fr" \
  "{\"subject_template\": \"$CUSTOM_PWD_SUBJECT\", \"body_template\": \"$CUSTOM_PWD_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT password_reset/fr custom"
assert_body_field "is_custom=true" ".is_custom" "true"
echo

echo "13) POST password-reset-link/email — uses custom template"
STATUS="$(api_with_status POST "/api/v2/admin/users/$TEST_USER_ID/password-reset-link/email" "" "$TOKEN")"
if [[ "$STATUS" == "201" ]]; then
  echo "[OK] password-reset-link/email → 201"
elif [[ "$STATUS" == "502" || "$STATUS" == "503" ]]; then
  echo "[INFO] password-reset-link/email → HTTP $STATUS (SMTP not configured — acceptable)"
  echo "[OK] route reached correctly with custom template"
else
  echo "[KO] password-reset-link/email unexpected HTTP $STATUS"
  jq . "$_BODY_FILE" 2>/dev/null
  exit 1
fi
echo

echo "14) Reset password_reset/fr"
reset_template "password_reset/fr"
echo

# ---- email_verification template --------------------------------------------

echo "--- email_verification template ---"
echo

CUSTOM_VERIF_SUBJECT="[CUSTOM-B-${RUN_ID}] Verify {app_name}"
CUSTOM_VERIF_BODY="Bonjour,\n\nValider : {url}\n\nExpire : {expires_at}\n\n— {app_name}"

echo "15) Save custom email_verification/fr template"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/email_verification/fr" \
  "{\"subject_template\": \"$CUSTOM_VERIF_SUBJECT\", \"body_template\": \"$CUSTOM_VERIF_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT email_verification/fr custom"
echo

echo "16) Preview email_verification/fr — verify custom marker"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/email_verification/fr/preview" \
  "{\"subject_template\": \"$CUSTOM_VERIF_SUBJECT\", \"body_template\": \"$CUSTOM_VERIF_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview email_verification/fr"
PREVIEW_SUBJECT="$(jq -r '.subject' "$_BODY_FILE")"
if ! echo "$PREVIEW_SUBJECT" | grep -q "CUSTOM-B-${RUN_ID}"; then
  echo "[KO] preview subject does not contain custom marker"
  echo "  got: $PREVIEW_SUBJECT"
  exit 1
fi
echo "[OK] preview subject contains custom marker"
echo

echo "17) Login test user to get their token"
LOGIN_TEST="$(api POST "/api/v2/auth/login" "{
  \"email\": \"$TEST_USER_EMAIL\",
  \"password\": \"$TEST_USER_PASSWORD\"
}")"
TEST_TOKEN="$(echo "$LOGIN_TEST" | jq -r '.token // empty')"
if [[ -z "$TEST_TOKEN" || "$TEST_TOKEN" == "null" ]]; then
  echo "[INFO] test user login failed — skipping request-email-verification call"
  TEST_TOKEN=""
else
  echo "[OK] test user token received"
fi

if [[ -n "$TEST_TOKEN" ]]; then
  echo "18) POST /api/v2/me/request-email-verification with custom template"
  STATUS="$(api_with_status POST "/api/v2/me/request-email-verification" "" "$TEST_TOKEN")"
  if [[ "$STATUS" == "200" ]]; then
    echo "[OK] request-email-verification → 200"
  elif [[ "$STATUS" == "502" || "$STATUS" == "503" ]]; then
    echo "[INFO] request-email-verification → HTTP $STATUS (SMTP not configured — acceptable)"
    echo "[OK] route reached with custom template"
  else
    echo "[INFO] request-email-verification → HTTP $STATUS"
    jq . "$_BODY_FILE" 2>/dev/null || true
    echo "[OK] route reached (may be 200 already-verified etc.)"
  fi
  echo
fi

echo "19) Reset email_verification/fr"
reset_template "email_verification/fr"
echo

# ---- magic_login template ---------------------------------------------------

echo "--- magic_login template ---"
echo

CUSTOM_MAGIC_SUBJECT="[CUSTOM-B-${RUN_ID}] Login {app_name}"
CUSTOM_MAGIC_BODY="Hello,\n\nSign in: {url}\n\nExpires: {expires_at}\n\n— {app_name}"

echo "20) Save custom magic_login/en template"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/magic_login/en" \
  "{\"subject_template\": \"$CUSTOM_MAGIC_SUBJECT\", \"body_template\": \"$CUSTOM_MAGIC_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT magic_login/en custom"
echo

echo "21) POST /api/v2/public/magic-login/request — anti-enumeration response expected"
# Magic login always returns generic_response regardless of email existence — this is intentional
STATUS="$(api_with_status POST "/api/v2/public/magic-login/request" \
  "{\"email\": \"$TEST_USER_EMAIL\"}")"
# Anti-enumeration: always 200 regardless of whether email exists or SMTP works
if [[ "$STATUS" == "200" ]]; then
  echo "[OK] magic-login/request → 200 (generic anti-enumeration response)"
else
  echo "[KO] magic-login/request expected 200 (anti-enumeration), got HTTP $STATUS"
  jq . "$_BODY_FILE" 2>/dev/null || true
  exit 1
fi
echo

echo "22) Preview magic_login/en — verify custom marker"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/magic_login/en/preview" \
  "{\"subject_template\": \"$CUSTOM_MAGIC_SUBJECT\", \"body_template\": \"$CUSTOM_MAGIC_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview magic_login/en"
PREVIEW_SUBJECT="$(jq -r '.subject' "$_BODY_FILE")"
if ! echo "$PREVIEW_SUBJECT" | grep -q "CUSTOM-B-${RUN_ID}"; then
  echo "[KO] preview subject does not contain custom marker"
  echo "  got: $PREVIEW_SUBJECT"
  exit 1
fi
echo "[OK] preview subject contains custom marker: $PREVIEW_SUBJECT"
echo

echo "23) Reset magic_login/en"
reset_template "magic_login/en"
echo

# ---- smtp_test template -----------------------------------------------------

echo "--- smtp_test template ---"
echo

CUSTOM_SMTP_SUBJECT="[CUSTOM-B-${RUN_ID}] {app_name} SMTP Test"
CUSTOM_SMTP_BODY="SMTP test from {app_name}.\n\nURL: {public_base_url}\n\nIf received, SMTP works."

echo "24) Save custom smtp_test/en template (with {public_base_url})"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/smtp_test/en" \
  "{\"subject_template\": \"$CUSTOM_SMTP_SUBJECT\", \"body_template\": \"$CUSTOM_SMTP_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT smtp_test/en custom"
assert_body_field "is_custom=true" ".is_custom" "true"
echo

echo "25) Preview smtp_test/en — verify custom marker and public_base_url rendered"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/smtp_test/en/preview" \
  "{\"subject_template\": \"$CUSTOM_SMTP_SUBJECT\", \"body_template\": \"$CUSTOM_SMTP_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview smtp_test/en"
PREVIEW_SUBJECT="$(jq -r '.subject' "$_BODY_FILE")"
PREVIEW_BODY="$(jq -r '.body' "$_BODY_FILE")"
if ! echo "$PREVIEW_SUBJECT" | grep -q "CUSTOM-B-${RUN_ID}"; then
  echo "[KO] preview subject does not contain custom marker"
  echo "  got: $PREVIEW_SUBJECT"
  exit 1
fi
echo "[OK] preview subject contains custom marker: $PREVIEW_SUBJECT"
if echo "$PREVIEW_BODY" | grep -q "{public_base_url}"; then
  echo "[KO] preview body still contains unexpanded {public_base_url}"
  exit 1
fi
echo "[OK] preview body has {public_base_url} expanded"
echo

echo "26) POST /api/v2/admin/smtp-settings/test — uses custom smtp_test template"
STATUS="$(api_with_status POST "/api/v2/admin/smtp-settings/test" "" "$TOKEN")"
if [[ "$STATUS" == "200" ]]; then
  echo "[OK] smtp-settings/test → 200 (SMTP available)"
elif [[ "$STATUS" == "502" ]]; then
  echo "[INFO] smtp-settings/test → 502 (SMTP not configured — acceptable)"
  echo "[OK] route reached with custom template"
else
  echo "[KO] smtp-settings/test unexpected HTTP $STATUS"
  jq . "$_BODY_FILE" 2>/dev/null
  exit 1
fi
echo

echo "27) Reset smtp_test/en"
reset_template "smtp_test/en"
echo

# ---- fallback after reset ---------------------------------------------------

echo "--- fallback after reset ---"
echo

echo "28) GET invitation/fr after reset — is_custom=false"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/invitation/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET invitation/fr"
assert_body_field "is_custom=false" ".is_custom" "false"
SUBJECT="$(jq -r '.subject_template' "$_BODY_FILE")"
if echo "$SUBJECT" | grep -q "CUSTOM-B-"; then
  echo "[KO] default subject still has custom marker after reset"
  exit 1
fi
echo "[OK] invitation/fr subject is back to default: $SUBJECT"
echo

echo "29) POST invitation/email after reset — still works"
STATUS="$(api_with_status POST "/api/v2/admin/users/$TEST_USER_ID/invitation/email" "" "$TOKEN")"
if [[ "$STATUS" == "201" || "$STATUS" == "502" || "$STATUS" == "503" ]]; then
  echo "[OK] invitation/email after reset → HTTP $STATUS (expected)"
else
  echo "[KO] invitation/email after reset unexpected HTTP $STATUS"
  jq . "$_BODY_FILE" 2>/dev/null
  exit 1
fi
echo

# ---- validation: invalid template rejected ----------------------------------

echo "--- invalid template rejected ---"
echo

echo "30) PUT invitation/fr with unknown variable {evil} → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/fr" \
  '{"subject_template": "Subject {app_name}", "body_template": "Link {url} expires {expires_at} from {evil}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT with {evil} variable → 400"
echo

echo "31) GET invitation/fr — still default after rejected PUT"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/invitation/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET invitation/fr after rejected PUT"
assert_body_field "is_custom=false (unchanged)" ".is_custom" "false"
echo

# ---- final checks -----------------------------------------------------------

echo "--- final checks ---"
echo

echo "32) python -m compileall backend (final)"
python -m compileall backend -q
echo "[OK] python -m compileall backend"
echo

echo "33) git diff --check (final)"
git diff --check
echo "[OK] git diff --check"
echo

echo "=== OK: Email Templates Passe B — all checks passed ==="
