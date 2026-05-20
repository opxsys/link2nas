#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%Y%m%d%H%M%S)-$$"

echo "=== Link2NAS — Email Templates Passe C ==="
echo "BASE_URL=$BASE_URL"
echo "RUN_ID=$RUN_ID"
echo

# ---- helpers ----------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}

_BODY_FILE="/tmp/l2n_etpl_c_test_$$.json"
USER_A_ID=""
USER_C_ID=""
USER_D_ID=""
USER_E_ID=""
ANN_BASE_ID=""
ANN_SEND_ID=""
TOKEN="${TOKEN:-}"

cleanup() {
  if [[ -n "$TOKEN" ]]; then
    # Reset announcement templates
    for KEY_LANG in "announcement/fr" "announcement/en"; do
      curl -sS -X POST "$BASE_URL/api/v2/admin/email-templates/$KEY_LANG/reset" \
        -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
    done

    # Delete known announcement IDs
    for ANN_ID in "$ANN_BASE_ID" "$ANN_SEND_ID"; do
      [[ -z "$ANN_ID" ]] && continue
      curl -sS -X DELETE "$BASE_URL/api/v2/admin/announcements/$ANN_ID" \
        -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
    done

    # Best-effort: find and delete any announcement with RUN_ID in title (catches 503-orphans)
    ANN_LIST="$(curl -sS -H "X-Api-Key: $TOKEN" "$BASE_URL/api/v2/admin/announcements" 2>/dev/null || echo "[]")"
    if echo "$ANN_LIST" | jq -e 'type == "array"' >/dev/null 2>&1; then
      while IFS= read -r ann_id; do
        [[ -z "$ann_id" || "$ann_id" == "null" ]] && continue
        curl -sS -X DELETE "$BASE_URL/api/v2/admin/announcements/$ann_id" \
          -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
      done < <(echo "$ANN_LIST" | jq -r --arg rid "$RUN_ID" '.[] | select(.title | contains($rid)) | .id')
    fi

    # Delete test users
    for USER_ID_TO_DELETE in "$USER_A_ID" "$USER_C_ID" "$USER_D_ID" "$USER_E_ID"; do
      [[ -z "$USER_ID_TO_DELETE" ]] && continue
      curl -sS -X DELETE "$BASE_URL/api/v2/admin/users/$USER_ID_TO_DELETE" \
        -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
    done
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
  echo "3) Login admin"
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

# ---- Passe A infra check ----------------------------------------------------

echo "--- Passe A infra check ---"
echo

echo "4) GET email-templates — at least 14 entries expected"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET email-templates"
COUNT="$(jq 'length' "$_BODY_FILE")"
if (( COUNT < 14 )); then
  echo "[KO] Expected at least 14 templates, got $COUNT"
  exit 1
fi
echo "[OK] $COUNT templates found"
echo

echo "5) GET announcement/fr → exists with is_custom=false"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/announcement/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET announcement/fr"
assert_body_field "announcement/fr is_custom=false" ".is_custom" "false"
echo

echo "6) GET announcement/en → exists with is_custom=false"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/announcement/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET announcement/en"
assert_body_field "announcement/en is_custom=false" ".is_custom" "false"
echo

# ---- targeted_email_recipients: baseline ------------------------------------

echo "--- targeted_email_recipients baseline ---"
echo

BASELINE_ANN_TITLE="[PASSE-C-${RUN_ID}] Baseline (send_email=false)"

echo "7) Create baseline announcement (send_email=false) → 201"
STATUS="$(api_with_status POST "/api/v2/admin/announcements" \
  "{\"title\": \"$BASELINE_ANN_TITLE\", \"body\": \"Baseline body.\", \"send_email\": false}" \
  "$TOKEN")"
assert_http "$STATUS" "201" "POST /admin/announcements baseline"
ANN_BASE_ID="$(jq -r '.id // empty' "$_BODY_FILE")"
if [[ -z "$ANN_BASE_ID" || "$ANN_BASE_ID" == "null" ]]; then
  echo "[KO] baseline announcement id missing"
  exit 1
fi
echo "[OK] baseline announcement id: $ANN_BASE_ID"
echo

echo "8) GET tracking baseline → capture targeted_email_recipients"
STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_BASE_ID/tracking" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET tracking baseline"
BASELINE_COUNT="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
if [[ -z "$BASELINE_COUNT" || "$BASELINE_COUNT" == "null" ]]; then
  echo "[KO] targeted_email_recipients missing from tracking"
  jq . "$_BODY_FILE" 2>/dev/null
  exit 1
fi
echo "[OK] baseline targeted_email_recipients=$BASELINE_COUNT"
if (( BASELINE_COUNT > 0 )); then
  echo "[WARN] Baseline > 0: pre-existing eligible users in system. email_sent+email_failed checks will reflect total eligible, not just test users."
fi
echo

# ---- ineligible users do NOT increment count --------------------------------

echo "--- ineligible users: no count increase ---"
echo

USER_C_EMAIL="test-passe-c-c-${RUN_ID}@test.local"
USER_C_PASSWORD="TestPasseCC123!"

echo "9) Create User C (active, email, email NOT verified)"
CREATE_C="$(api POST "/api/v2/admin/users" "{
  \"email\": \"$USER_C_EMAIL\",
  \"display_name\": \"Test Passe C - C (unverified)\",
  \"password\": \"$USER_C_PASSWORD\"
}" "$TOKEN")"
assert_no_error "$CREATE_C" "User C created"
USER_C_ID="$(echo "$CREATE_C" | jq -r '.id // empty')"
if [[ -z "$USER_C_ID" || "$USER_C_ID" == "null" ]]; then
  echo "[KO] User C id missing"; exit 1
fi
echo "[OK] User C id: $USER_C_ID (email_verified=false)"
echo

echo "10) GET tracking → count must NOT change after User C"
STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_BASE_ID/tracking" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET tracking after User C"
COUNT_AFTER_C="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
assert_equals "$COUNT_AFTER_C" "$BASELINE_COUNT" "count unchanged after unverified User C"
echo

USER_D_EMAIL="test-passe-c-d-${RUN_ID}@test.local"
USER_D_PASSWORD="TestPasseCD123!"

echo "11) Create User D (active, email_verified=true, receive_application_emails not set → false)"
CREATE_D="$(api POST "/api/v2/admin/users" "{
  \"email\": \"$USER_D_EMAIL\",
  \"display_name\": \"Test Passe C - D (no receive)\",
  \"password\": \"$USER_D_PASSWORD\",
  \"email_verified\": true
}" "$TOKEN")"
assert_no_error "$CREATE_D" "User D created"
USER_D_ID="$(echo "$CREATE_D" | jq -r '.id // empty')"
if [[ -z "$USER_D_ID" || "$USER_D_ID" == "null" ]]; then
  echo "[KO] User D id missing"; exit 1
fi
echo "[OK] User D id: $USER_D_ID (email_verified=true, receive_application_emails=false)"
echo

echo "12) GET tracking → count must NOT change after User D"
STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_BASE_ID/tracking" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET tracking after User D"
COUNT_AFTER_D="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
assert_equals "$COUNT_AFTER_D" "$BASELINE_COUNT" "count unchanged after User D (no receive_application_emails)"
echo

# ---- eligible User A increments count ---------------------------------------

echo "--- eligible User A (preferred_language=fr) ---"
echo

USER_A_EMAIL="test-passe-c-a-${RUN_ID}@test.local"
USER_A_PASSWORD="TestPasseCA123!"

echo "13) Create User A (email_verified=true, preferred_language=fr)"
CREATE_A="$(api POST "/api/v2/admin/users" "{
  \"email\": \"$USER_A_EMAIL\",
  \"display_name\": \"Test Passe C - A (eligible, fr)\",
  \"password\": \"$USER_A_PASSWORD\",
  \"email_verified\": true,
  \"preferred_language\": \"fr\"
}" "$TOKEN")"
assert_no_error "$CREATE_A" "User A created"
USER_A_ID="$(echo "$CREATE_A" | jq -r '.id // empty')"
if [[ -z "$USER_A_ID" || "$USER_A_ID" == "null" ]]; then
  echo "[KO] User A id missing"; exit 1
fi
echo "[OK] User A id: $USER_A_ID (preferred_language=fr)"
echo

echo "14) Login as User A"
LOGIN_A="$(api POST "/api/v2/auth/login" "{
  \"email\": \"$USER_A_EMAIL\",
  \"password\": \"$USER_A_PASSWORD\"
}")"
USER_A_TOKEN="$(echo "$LOGIN_A" | jq -r '.token // empty')"
if [[ -z "$USER_A_TOKEN" || "$USER_A_TOKEN" == "null" ]]; then
  echo "[KO] User A login failed"
  echo "$LOGIN_A" | jq
  exit 1
fi
echo "[OK] User A token received"
echo

echo "15) PATCH /api/v2/me receive_application_emails=true (User A)"
STATUS="$(api_with_status PATCH "/api/v2/me" \
  '{"receive_application_emails": true}' \
  "$USER_A_TOKEN")"
assert_http "$STATUS" "200" "PATCH /me receive_application_emails=true (User A)"
assert_body_field "receive_application_emails=true" ".receive_application_emails" "true"
echo

EXPECTED_COUNT_A="$(( BASELINE_COUNT + 1 ))"
echo "16) GET tracking → count must be baseline+1 ($EXPECTED_COUNT_A)"
STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_BASE_ID/tracking" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET tracking after User A opted in"
COUNT_AFTER_A="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
assert_equals "$COUNT_AFTER_A" "$EXPECTED_COUNT_A" "count = baseline+1 after eligible User A"
echo

# ---- User E: eligible then disabled -----------------------------------------

echo "--- User E: eligible then disabled (is_active=false) ---"
echo

USER_E_EMAIL="test-passe-c-e-${RUN_ID}@test.local"
USER_E_PASSWORD="TestPasseCE123!"

echo "17) Create User E (email_verified=true)"
CREATE_E="$(api POST "/api/v2/admin/users" "{
  \"email\": \"$USER_E_EMAIL\",
  \"display_name\": \"Test Passe C - E (will be disabled)\",
  \"password\": \"$USER_E_PASSWORD\",
  \"email_verified\": true
}" "$TOKEN")"
assert_no_error "$CREATE_E" "User E created"
USER_E_ID="$(echo "$CREATE_E" | jq -r '.id // empty')"
if [[ -z "$USER_E_ID" || "$USER_E_ID" == "null" ]]; then
  echo "[KO] User E id missing"; exit 1
fi
echo "[OK] User E id: $USER_E_ID"
echo

echo "18) Login as User E"
LOGIN_E="$(api POST "/api/v2/auth/login" "{
  \"email\": \"$USER_E_EMAIL\",
  \"password\": \"$USER_E_PASSWORD\"
}")"
USER_E_TOKEN="$(echo "$LOGIN_E" | jq -r '.token // empty')"
if [[ -z "$USER_E_TOKEN" || "$USER_E_TOKEN" == "null" ]]; then
  echo "[KO] User E login failed"
  echo "$LOGIN_E" | jq
  exit 1
fi
echo "[OK] User E token received"
echo

echo "19) PATCH /api/v2/me receive_application_emails=true (User E)"
STATUS="$(api_with_status PATCH "/api/v2/me" \
  '{"receive_application_emails": true}' \
  "$USER_E_TOKEN")"
assert_http "$STATUS" "200" "PATCH /me receive_application_emails=true (User E)"
echo

EXPECTED_COUNT_AE="$(( BASELINE_COUNT + 2 ))"
echo "20) GET tracking → count must be baseline+2 ($EXPECTED_COUNT_AE) — both A and E eligible"
STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_BASE_ID/tracking" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET tracking after User E opted in"
COUNT_AFTER_E="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
assert_equals "$COUNT_AFTER_E" "$EXPECTED_COUNT_AE" "count = baseline+2 with A and E both eligible"
echo

echo "21) POST /admin/users/{E_ID}/disable"
STATUS="$(api_with_status POST "/api/v2/admin/users/$USER_E_ID/disable" "" "$TOKEN")"
assert_http "$STATUS" "200" "POST disable User E"
echo

echo "22) GET tracking → count must be baseline+1 again (E disabled → ineligible)"
STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_BASE_ID/tracking" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET tracking after User E disabled"
COUNT_E_DISABLED="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
assert_equals "$COUNT_E_DISABLED" "$EXPECTED_COUNT_A" "count back to baseline+1 after disabling User E"
echo

# ---- User A opt-out / re-opt-in ---------------------------------------------

echo "--- User A opt-out / re-opt-in ---"
echo

echo "23) PATCH /api/v2/me receive_application_emails=false (User A opt-out)"
STATUS="$(api_with_status PATCH "/api/v2/me" \
  '{"receive_application_emails": false}' \
  "$USER_A_TOKEN")"
assert_http "$STATUS" "200" "PATCH /me receive_application_emails=false (User A)"
echo

echo "24) GET tracking → count back to baseline after User A opts out"
STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_BASE_ID/tracking" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET tracking after User A opted out"
COUNT_OPT_OUT="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
assert_equals "$COUNT_OPT_OUT" "$BASELINE_COUNT" "count back to baseline after opt-out"
echo

echo "25) PATCH /api/v2/me receive_application_emails=true (User A re-opt-in)"
STATUS="$(api_with_status PATCH "/api/v2/me" \
  '{"receive_application_emails": true}' \
  "$USER_A_TOKEN")"
assert_http "$STATUS" "200" "PATCH /me receive_application_emails=true (User A re-opt-in)"
echo

# ---- custom announcement/fr template (set BEFORE send_email=true) -----------

echo "--- custom announcement/fr template ---"
echo

CUSTOM_ANN_SUBJECT="[CUSTOM-C-${RUN_ID}] {title}"
CUSTOM_ANN_BODY="Bonjour,\n\n{body}\n\nType: {type} | Sévérité: {severity}\n{action_text}\nDébut: {starts_at}\nFin: {ends_at}\n\n— {app_name}"

echo "26) PUT announcement/fr custom → 200, is_custom=true"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/announcement/fr" \
  "{\"subject_template\": \"$CUSTOM_ANN_SUBJECT\", \"body_template\": \"$CUSTOM_ANN_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT announcement/fr custom"
assert_body_field "is_custom=true" ".is_custom" "true"
echo

echo "27) Preview announcement/fr — subject must contain CUSTOM-C-$RUN_ID"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/announcement/fr/preview" \
  "{\"subject_template\": \"$CUSTOM_ANN_SUBJECT\", \"body_template\": \"$CUSTOM_ANN_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview announcement/fr"
PREVIEW_SUBJECT="$(jq -r '.subject' "$_BODY_FILE")"
if ! echo "$PREVIEW_SUBJECT" | grep -q "CUSTOM-C-${RUN_ID}"; then
  echo "[KO] preview subject does not contain CUSTOM-C-RUN_ID marker"
  echo "  got: $PREVIEW_SUBJECT"
  exit 1
fi
echo "[OK] preview subject contains CUSTOM-C-RUN_ID marker: $PREVIEW_SUBJECT"
echo

echo "28) Preview body: {action_text} placeholder must be expanded"
PREVIEW_BODY="$(jq -r '.body' "$_BODY_FILE")"
if echo "$PREVIEW_BODY" | grep -qF '{action_text}'; then
  echo "[KO] preview body still contains unexpanded {action_text}"
  echo "  body: $PREVIEW_BODY"
  exit 1
fi
echo "[OK] preview body has {action_text} expanded"
echo

echo "29) Preview body: {title} placeholder must be expanded"
if echo "$PREVIEW_BODY" | grep -qF '{title}'; then
  echo "[KO] preview body still contains unexpanded {title}"
  exit 1
fi
echo "[OK] preview body has {title} expanded"
echo

# ---- announcement with send_email=true + tracking ---------------------------

echo "--- announcement with send_email=true ---"
echo

ANN_SEND_TITLE="[PASSE-C-${RUN_ID}] Test send_email=true"

echo "30) POST announcement with send_email=true → 201 (SMTP) or 503 (no SMTP)"
STATUS="$(api_with_status POST "/api/v2/admin/announcements" \
  "{\"title\": \"$ANN_SEND_TITLE\", \"body\": \"Email send test.\", \"send_email\": true}" \
  "$TOKEN")"

if [[ "$STATUS" == "201" ]]; then
  ANN_SEND_ID="$(jq -r '.id // empty' "$_BODY_FILE")"
  if [[ -z "$ANN_SEND_ID" || "$ANN_SEND_ID" == "null" ]]; then
    echo "[KO] send_email=true announcement id missing in 201 response"
    exit 1
  fi
  echo "[OK] announcement with send_email=true → 201, id=$ANN_SEND_ID"
  echo

  echo "30a) GET tracking for send_email announcement"
  STATUS="$(api_with_status GET "/api/v2/admin/announcements/$ANN_SEND_ID/tracking" "" "$TOKEN")"
  assert_http "$STATUS" "200" "GET tracking send_email announcement"

  echo "30b) stats.targeted_email_recipients == baseline+1 ($EXPECTED_COUNT_A)"
  SEND_TARGETED="$(jq -r '.stats.targeted_email_recipients' "$_BODY_FILE")"
  assert_equals "$SEND_TARGETED" "$EXPECTED_COUNT_A" "targeted_email_recipients == baseline+1 at send time"

  EMAIL_SENT="$(jq -r '.stats.email_sent' "$_BODY_FILE")"
  EMAIL_FAILED="$(jq -r '.stats.email_failed' "$_BODY_FILE")"
  EMAIL_TOTAL=$(( EMAIL_SENT + EMAIL_FAILED ))
  echo "30c) email_sent=$EMAIL_SENT, email_failed=$EMAIL_FAILED → total=$EMAIL_TOTAL"
  if (( EMAIL_TOTAL < 1 )); then
    echo "[KO] expected at least 1 email attempt (sent+failed), got $EMAIL_TOTAL"
    exit 1
  fi
  echo "[OK] at least 1 email attempt recorded (email_sent+email_failed=$EMAIL_TOTAL)"

  echo "30d) User A must appear in reads with email_status 'sent' or 'failed'"
  USER_A_STATUS="$(jq -r --arg uid "$USER_A_ID" '.reads[] | select(.user_id == $uid) | .email_status // empty' "$_BODY_FILE")"
  if [[ -z "$USER_A_STATUS" || "$USER_A_STATUS" == "null" ]]; then
    echo "[KO] User A ($USER_A_ID) not found in reads"
    jq '[.reads[] | {user_id, email_status}]' "$_BODY_FILE" 2>/dev/null
    exit 1
  fi
  if [[ "$USER_A_STATUS" != "sent" && "$USER_A_STATUS" != "failed" ]]; then
    echo "[KO] User A email_status expected 'sent' or 'failed', got '$USER_A_STATUS'"
    exit 1
  fi
  echo "[OK] User A email_status=$USER_A_STATUS"
  if [[ "$USER_A_STATUS" == "failed" ]]; then
    USER_A_ERR="$(jq -r --arg uid "$USER_A_ID" '.reads[] | select(.user_id == $uid) | .email_error // empty' "$_BODY_FILE")"
    echo "[INFO] User A email error (truncated): ${USER_A_ERR:0:120}"
  fi

  echo "30e) Users C, D, E must NOT appear in reads"
  for CHECK_ID in "$USER_C_ID" "$USER_D_ID" "$USER_E_ID"; do
    [[ -z "$CHECK_ID" ]] && continue
    IN_READS="$(jq -r --arg uid "$CHECK_ID" '[.reads[] | select(.user_id == $uid)] | length' "$_BODY_FILE")"
    if (( IN_READS > 0 )); then
      echo "[KO] Ineligible user $CHECK_ID should not appear in reads, but found $IN_READS entry(ies)"
      exit 1
    fi
  done
  echo "[OK] Users C, D, E not in reads (not targeted)"

elif [[ "$STATUS" == "503" ]]; then
  echo "[INFO] announcement with send_email=true → 503 (SMTP not configured — acceptable)"
  echo "[INFO] Tracking assertions skipped (no email was sent)"
  echo "[OK] route correctly returned 503 when SMTP unavailable"
else
  echo "[KO] unexpected HTTP $STATUS for send_email=true"
  jq . "$_BODY_FILE" 2>/dev/null
  exit 1
fi
echo

# ---- invalid variable rejected -----------------------------------------------

echo "--- invalid template variable rejected ---"
echo

echo "31) PUT announcement/fr with unknown variable {evil} → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/announcement/fr" \
  '{"subject_template": "Subject {title}", "body_template": "{body} — {evil}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT announcement/fr with {evil} → 400"
echo

echo "32) GET announcement/fr — is_custom=true, no {evil} in template (rejected PUT not persisted)"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/announcement/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET announcement/fr after rejected PUT"
assert_body_field "is_custom=true (unchanged after rejected PUT)" ".is_custom" "true"
CURRENT_SUBJECT="$(jq -r '.subject_template' "$_BODY_FILE")"
if echo "$CURRENT_SUBJECT" | grep -q "evil"; then
  echo "[KO] rejected template was persisted — subject_template contains 'evil'"
  exit 1
fi
echo "[OK] announcement/fr still has previous custom template (no evil)"
echo

# ---- reset template ----------------------------------------------------------

echo "--- reset announcement/fr ---"
echo

echo "33) POST announcement/fr/reset → 200"
reset_template "announcement/fr"
echo

echo "34) GET announcement/fr after reset → is_custom=false, no custom marker"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/announcement/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET announcement/fr after reset"
assert_body_field "is_custom=false after reset" ".is_custom" "false"
SUBJECT_AFTER_RESET="$(jq -r '.subject_template' "$_BODY_FILE")"
if echo "$SUBJECT_AFTER_RESET" | grep -q "CUSTOM-C-"; then
  echo "[KO] subject still has custom marker after reset"
  exit 1
fi
echo "[OK] announcement/fr back to default subject: $SUBJECT_AFTER_RESET"
echo

echo "35) GET announcement/en still is_custom=false (untouched)"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/announcement/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET announcement/en still default"
assert_body_field "announcement/en is_custom=false (unchanged)" ".is_custom" "false"
echo

# ---- final checks -----------------------------------------------------------

echo "--- final checks ---"
echo

echo "36) python -m compileall backend (final)"
python -m compileall backend -q
echo "[OK] python -m compileall backend"
echo

echo "37) git diff --check (final)"
git diff --check
echo "[OK] git diff --check"
echo

echo "=== OK: Email Templates Passe C — all checks passed ==="
