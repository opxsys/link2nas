#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%Y%m%d%H%M%S)-$$"

echo "=== Link2NAS — Email Templates Passe A ==="
echo "BASE_URL=$BASE_URL"
echo "RUN_ID=$RUN_ID"
echo

# ---- helpers ----------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}

_BODY_FILE="/tmp/l2n_etpl_test_$$.json"

cleanup() {
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

echo "3) Setup status"
SETUP_STATUS="$(api GET "/api/v2/setup/status")"
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
  echo "4) Create first admin"
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
  echo "5) Login admin"
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

# ---- ensure_defaults --------------------------------------------------------

echo "--- ensure_defaults ---"
echo

echo "6) List all templates — expect 16 entries (8 keys × fr/en)"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET /email-templates"

COUNT="$(jq 'length' "$_BODY_FILE")"
assert_equals "$COUNT" "16" "template count = 16"

# Verify all expected keys are present
KEYS_FOUND="$(jq -r '.[].template_key' "$_BODY_FILE" | sort -u | tr '\n' ',')"
for KEY in invitation password_reset email_verification magic_login smtp_test announcement notification_event notification_test; do
  if ! echo "$KEYS_FOUND" | grep -q "$KEY"; then
    echo "[KO] Missing template key: $KEY"
    exit 1
  fi
  echo "[OK] template key present: $KEY"
done

# Verify fr and en are present
LANGS_FOUND="$(jq -r '.[].language' "$_BODY_FILE" | sort -u | paste -sd ',' -)"
assert_equals "$LANGS_FOUND" "en,fr" "both languages present"
echo

# ---- GET specific template --------------------------------------------------

echo "--- GET specific template ---"
echo

echo "7) GET invitation/fr"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/invitation/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET invitation/fr"
assert_body_field "template_key = invitation" ".template_key" "invitation"
assert_body_field "language = fr" ".language" "fr"
assert_body_field "is_custom = false" ".is_custom" "false"
assert_body_non_empty "subject_template non-empty" ".subject_template"
assert_body_non_empty "body_template non-empty" ".body_template"
assert_body_non_empty "available_variables non-empty" ".available_variables[0]"
echo

echo "8) GET notification_event/en"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_event/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_event/en"
assert_body_field "is_custom = false" ".is_custom" "false"
assert_body_non_empty "subject_template" ".subject_template"
echo

echo "9) GET smtp_test/fr"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/smtp_test/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET smtp_test/fr"
assert_body_non_empty "subject_template" ".subject_template"
echo

# ---- GET validation errors --------------------------------------------------

echo "--- validation errors ---"
echo

echo "10) GET unknown template key → 404"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/unknown_key/fr" "" "$TOKEN")"
assert_http "$STATUS" "404" "GET unknown_key/fr → 404"
echo

echo "11) GET unsupported language → 400"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/invitation/xx" "" "$TOKEN")"
assert_http "$STATUS" "400" "GET invitation/xx → 400"
echo

# ---- PUT custom template ----------------------------------------------------

echo "--- PUT custom template ---"
echo

CUSTOM_SUBJECT="[Test] {app_name} — Invitation"
CUSTOM_BODY="Hello,\n\nYou have been invited to {app_name}.\n\nActivate here: {url}\n\nExpires: {expires_at}"

echo "12) PUT valid custom template — invitation/en"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/en" \
  "{\"subject_template\": \"$CUSTOM_SUBJECT\", \"body_template\": \"$CUSTOM_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT invitation/en"
assert_body_field "is_custom = true" ".is_custom" "true"
assert_body_field "subject saved" ".subject_template" "$CUSTOM_SUBJECT"
echo

echo "13) GET invitation/en — verify persisted"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/invitation/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET invitation/en after PUT"
assert_body_field "is_custom = true (persisted)" ".is_custom" "true"
assert_body_field "subject persisted" ".subject_template" "$CUSTOM_SUBJECT"
echo

# ---- PUT validation errors --------------------------------------------------

echo "--- PUT validation errors ---"
echo

echo "14) PUT empty subject → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/en" \
  '{"subject_template": "", "body_template": "Hello {app_name}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT empty subject → 400"
echo

echo "15) PUT empty body → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/en" \
  '{"subject_template": "Hello {app_name}", "body_template": ""}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT empty body → 400"
echo

echo "16) PUT unknown variable in subject → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/en" \
  '{"subject_template": "Hello {hacker}", "body_template": "Link: {url} expires {expires_at} for {app_name}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT unknown variable {hacker} → 400"
ERROR_MSG="$(jq -r '.error' "$_BODY_FILE")"
if ! echo "$ERROR_MSG" | grep -q "hacker"; then
  echo "[KO] Error message should mention the unknown variable, got: $ERROR_MSG"
  exit 1
fi
echo "[OK] error message mentions unknown variable"
echo

echo "17) PUT unknown variable in body → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/en" \
  '{"subject_template": "{app_name} Invitation", "body_template": "Hello, here is your link {url} and {expires_at} - but also {injection}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT unknown variable in body → 400"
echo

echo "18) PUT unknown template key → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/does_not_exist/en" \
  '{"subject_template": "Subject", "body_template": "Body"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT unknown template key → 400"
echo

echo "19) PUT unsupported language → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/invitation/es" \
  '{"subject_template": "Subject {app_name}", "body_template": "Body {url} {expires_at} {app_name}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT invitation/es → 400"
echo

# ---- POST preview -----------------------------------------------------------

echo "--- POST preview ---"
echo

echo "20) POST preview — invitation/fr with valid templates"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/invitation/fr/preview" \
  '{"subject_template": "Bienvenue sur {app_name}", "body_template": "Bonjour,\n\nLien : {url}\n\nExpire : {expires_at}\n\n— {app_name}"}' \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview invitation/fr"
assert_body_non_empty "rendered subject non-empty" ".subject"
assert_body_non_empty "rendered body non-empty" ".body"
assert_body_non_empty "sample_values present" ".sample_values.app_name"

RENDERED_SUBJECT="$(jq -r '.subject' "$_BODY_FILE")"
if echo "$RENDERED_SUBJECT" | grep -q "{app_name}"; then
  echo "[KO] preview subject still contains unexpanded {app_name}"
  exit 1
fi
echo "[OK] preview subject has no unexpanded variables"
echo

echo "21) POST preview — announcement/en"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/announcement/en/preview" \
  '{"subject_template": "[{app_name}] {title}", "body_template": "Hello,\n\n{body}\n\n{action_text}\n\n{url}\n\n— {app_name}"}' \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview announcement/en"
assert_body_non_empty "rendered subject" ".subject"
echo

echo "22) POST preview — unknown variable → 400"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/invitation/fr/preview" \
  '{"subject_template": "{app_name}", "body_template": "Link {url} expires {expires_at} from {evil_var}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "POST preview with unknown variable → 400"
echo

echo "23) POST preview — empty subject → 400"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/invitation/fr/preview" \
  '{"subject_template": "", "body_template": "Body {url}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "POST preview empty subject → 400"
echo

# ---- POST reset -------------------------------------------------------------

echo "--- POST reset ---"
echo

echo "24) POST reset — invitation/en (was custom)"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/invitation/en/reset" "" "$TOKEN")"
assert_http "$STATUS" "200" "POST reset invitation/en"
assert_body_field "is_custom = false after reset" ".is_custom" "false"

RESET_SUBJECT="$(jq -r '.subject_template' "$_BODY_FILE")"
if [[ "$RESET_SUBJECT" == "$CUSTOM_SUBJECT" ]]; then
  echo "[KO] subject was not reset — still has custom value"
  exit 1
fi
echo "[OK] subject has been reset to default"
echo

echo "25) GET invitation/en — verify reset persisted"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/invitation/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET invitation/en after reset"
assert_body_field "is_custom = false (persisted)" ".is_custom" "false"
CURRENT_SUBJECT="$(jq -r '.subject_template' "$_BODY_FILE")"
if [[ "$CURRENT_SUBJECT" == "$CUSTOM_SUBJECT" ]]; then
  echo "[KO] reset was not persisted"
  exit 1
fi
echo "[OK] reset persisted correctly"
echo

echo "26) POST reset — unknown key → 400"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/unknown_key/fr/reset" "" "$TOKEN")"
assert_http "$STATUS" "400" "POST reset unknown_key → 400"
echo

# ---- ensure_defaults idempotency --------------------------------------------

echo "--- ensure_defaults idempotency ---"
echo

echo "27) List templates again — count must still be 16 (ensure_defaults does not duplicate)"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET /email-templates (2nd pass)"
COUNT2="$(jq 'length' "$_BODY_FILE")"
assert_equals "$COUNT2" "16" "template count still 16 after operations"
echo

# ---- access control ---------------------------------------------------------

echo "--- access control ---"
echo

echo "28) GET email-templates without token → 401"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates")"
assert_http "$STATUS" "401" "GET without token → 401"
echo

# ---- final checks -----------------------------------------------------------

echo "--- final checks ---"
echo

echo "29) python -m compileall backend (final)"
python -m compileall backend -q
echo "[OK] python -m compileall backend"
echo

echo "30) git diff --check (final)"
git diff --check
echo "[OK] git diff --check"
echo

echo "=== OK: Email Templates Passe A — all checks passed ==="
