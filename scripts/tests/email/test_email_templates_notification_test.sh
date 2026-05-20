#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%Y%m%d%H%M%S)-$$"

echo "=== Link2NAS — Email Templates notification_test ==="
echo "BASE_URL=$BASE_URL"
echo "RUN_ID=$RUN_ID"
echo

# ---- helpers ----------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}

_BODY_FILE="/tmp/l2n_notif_test_$$.json"

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

# ---- auth -------------------------------------------------------------------

echo "--- auth ---"
echo

SETUP_STATUS="$(api GET "/api/v2/setup/status")"
SETUP_REQUIRED="$(echo "$SETUP_STATUS" | jq -r '.setup_required')"

if [[ "$SETUP_REQUIRED" == "true" ]]; then
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
  LOGIN="$(api POST "/api/v2/auth/login" "{
    \"email\":\"$ADMIN_EMAIL\",
    \"password\":\"$ADMIN_PASSWORD\"
  }")"
  assert_no_error "$LOGIN" "admin login"
  TOKEN="$(echo "$LOGIN" | jq -r '.api_key')"
  echo "[OK] admin login OK"
fi
echo

# ---- GET notification_test/fr ----------------------------------------------

echo "--- GET notification_test ---"
echo

echo "3) GET notification_test/fr"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_test/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_test/fr"
assert_body_field "template_key = notification_test" ".template_key" "notification_test"
assert_body_field "language = fr" ".language" "fr"
assert_body_non_empty "subject_template non-empty" ".subject_template"
assert_body_non_empty "body_template non-empty" ".body_template"
assert_body_non_empty "available_variables non-empty" ".available_variables[0]"

# Check expected variables are present
VARS="$(jq -r '.available_variables | join(",")' "$_BODY_FILE")"
for VAR in app_name channel_name channel to_email config_id public_base_url; do
  if ! echo "$VARS" | grep -q "$VAR"; then
    echo "[KO] Missing variable in available_variables: $VAR"
    exit 1
  fi
  echo "[OK] variable $VAR present"
done
echo

echo "4) GET notification_test/en"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_test/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_test/en"
assert_body_field "template_key = notification_test" ".template_key" "notification_test"
assert_body_field "language = en" ".language" "en"
assert_body_non_empty "subject_template non-empty" ".subject_template"
assert_body_non_empty "body_template non-empty" ".body_template"
echo

# ---- PUT custom notification_test/fr ----------------------------------------

echo "--- PUT custom notification_test ---"
echo

CUSTOM_MARKER="[CUSTOM-TEST-$RUN_ID]"
CUSTOM_SUBJECT="$CUSTOM_MARKER [{app_name}] Test notification"
CUSTOM_BODY="$CUSTOM_MARKER\n\nCanal : {channel_name}\nDestinataire : {to_email}\nConfig : {config_id}\n\n— {app_name}"

echo "5) PUT valid custom — notification_test/fr"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/notification_test/fr" \
  "{\"subject_template\": \"$CUSTOM_SUBJECT\", \"body_template\": \"$CUSTOM_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT notification_test/fr"
assert_body_field "subject saved" ".subject_template" "$CUSTOM_SUBJECT"
assert_body_field "is_custom = true" ".is_custom" "true"
echo

echo "6) GET notification_test/fr — custom persisted"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_test/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_test/fr after PUT"
assert_body_field "subject persisted" ".subject_template" "$CUSTOM_SUBJECT"
assert_body_field "is_custom = true (persisted)" ".is_custom" "true"
echo

# ---- POST preview -----------------------------------------------------------

echo "--- POST preview ---"
echo

echo "7) POST preview — notification_test/fr with valid template"
PREVIEW_SUBJ="[{app_name}] Test — {channel_name}"
PREVIEW_BODY="Canal : {channel}\nDest : {to_email}\nConfig : {config_id}\n— {app_name}"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/notification_test/fr/preview" \
  "{\"subject_template\": \"$PREVIEW_SUBJ\", \"body_template\": \"$PREVIEW_BODY\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview notification_test/fr"
assert_body_non_empty "rendered subject non-empty" ".subject"
assert_body_non_empty "rendered body non-empty" ".body"
assert_body_non_empty "sample_values.app_name present" ".sample_values.app_name"
assert_body_non_empty "sample_values.channel_name present" ".sample_values.channel_name"
assert_body_non_empty "sample_values.to_email present" ".sample_values.to_email"

RENDERED_SUBJ="$(jq -r '.subject' "$_BODY_FILE")"
if echo "$RENDERED_SUBJ" | grep -qE '\{[a-z_]+\}'; then
  echo "[KO] preview subject still contains unexpanded variable placeholders: $RENDERED_SUBJ"
  exit 1
fi
echo "[OK] preview subject has no unexpanded variables"

RENDERED_BODY="$(jq -r '.body' "$_BODY_FILE")"
if echo "$RENDERED_BODY" | grep -qE '\{[a-z_]+\}'; then
  echo "[KO] preview body still contains unexpanded variable placeholders"
  exit 1
fi
echo "[OK] preview body has no unexpanded variables"
echo

echo "8) POST preview — notification_test/en with valid template"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/notification_test/en/preview" \
  '{"subject_template": "[{app_name}] Test notification", "body_template": "Channel: {channel}\nRecipient: {to_email}\nConfig: {config_id}\n— {app_name}"}' \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview notification_test/en"
assert_body_non_empty "rendered subject" ".subject"
echo

echo "9) POST preview — unknown variable {evil} → 400"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/notification_test/fr/preview" \
  '{"subject_template": "[{app_name}] Test", "body_template": "Canal : {channel_name} {evil}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "POST preview with unknown variable {evil} → 400"
echo

echo "10) PUT unknown variable {evil} in subject → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/notification_test/fr" \
  '{"subject_template": "[{app_name}] {evil}", "body_template": "Canal : {channel_name}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT unknown variable {evil} in subject → 400"
echo

echo "11) PUT unknown variable {evil} in body → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/notification_test/fr" \
  '{"subject_template": "[{app_name}] Test", "body_template": "{channel_name} {evil}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT unknown variable {evil} in body → 400"
echo

# ---- API test canal non sauvegardé ------------------------------------------

echo "--- API test canal non sauvegardé (POST /api/v2/settings/notification/test) ---"
echo
echo "[INFO] Ce test vérifie le format de la réponse. L'envoi réel nécessite SMTP configuré."
echo

echo "12) Test canal email non sauvegardé — sans SMTP configuré → 400 ou ok"
STATUS="$(api_with_status POST "/api/v2/settings/notification/test" \
  '{"channel": "email", "name": "Mon canal test", "config": {}}' \
  "$TOKEN")"
if [[ "$STATUS" == "200" ]]; then
  assert_body_field "ok = true" ".ok" "true"
  assert_body_non_empty "message non-empty" ".message"
  echo "[OK] Test email non sauvegardé → ok (SMTP configuré)"
elif [[ "$STATUS" == "400" ]]; then
  ERR="$(jq -r '.error' "$_BODY_FILE")"
  echo "[OK] Test email non sauvegardé → 400 attendu si SMTP absent ($ERR)"
else
  echo "[KO] Test email non sauvegardé: HTTP $STATUS inattendu"
  jq . "$_BODY_FILE"
  exit 1
fi
echo

echo "13) Test canal gotify non sauvegardé sans config → 400"
STATUS="$(api_with_status POST "/api/v2/settings/notification/test" \
  '{"channel": "gotify", "name": "Mon gotify", "config": {}}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "Test gotify sans server_url/token → 400"
echo

echo "14) Test canal webhook non sauvegardé sans url → 400"
STATUS="$(api_with_status POST "/api/v2/settings/notification/test" \
  '{"channel": "webhook", "name": "Mon webhook", "config": {}}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "Test webhook sans url → 400"
echo

# ---- Créer un canal email et tester (stored) ---------------------------------

echo "--- Canal email sauvegardé ---"
echo

echo "15) Créer canal email de test (sans to_email)"
CREATE_RESP="$(api POST "/api/v2/notifications/configs" \
  "{\"name\": \"Canal test $RUN_ID\", \"channel\": \"email\", \"config\": {}, \"is_enabled\": true, \"is_default\": false}" \
  "$TOKEN")"
if echo "$CREATE_RESP" | jq -e '.error' > /dev/null 2>&1; then
  echo "[SKIP] Création canal email échouée (SMTP non dispo pour création) — skip tests stored"
  echo "[INFO] Réponse : $(echo "$CREATE_RESP" | jq -r '.error')"
else
  CONFIG_ID="$(echo "$CREATE_RESP" | jq -r '.id')"
  if [[ -z "$CONFIG_ID" || "$CONFIG_ID" == "null" ]]; then
    echo "[SKIP] id canal email absent — skip tests stored"
  else
    echo "[OK] Canal email créé — id=$CONFIG_ID"

    echo "16) Test canal sauvegardé (POST /api/v2/notifications/configs/$CONFIG_ID/test)"
    STATUS="$(api_with_status POST "/api/v2/notifications/configs/$CONFIG_ID/test" "" "$TOKEN")"
    if [[ "$STATUS" == "200" ]]; then
      assert_body_field "ok = true" ".ok" "true"
      assert_body_non_empty "message non-empty" ".message"
      echo "[OK] Test canal sauvegardé → ok (SMTP configuré)"
    elif [[ "$STATUS" == "400" ]]; then
      ERR="$(jq -r '.error' "$_BODY_FILE")"
      echo "[OK] Test canal sauvegardé → 400 attendu si SMTP absent ($ERR)"
    else
      echo "[KO] Test canal sauvegardé: HTTP $STATUS inattendu"
      jq . "$_BODY_FILE"
      exit 1
    fi
    echo

    echo "17) Supprimer le canal de test"
    STATUS="$(api_with_status DELETE "/api/v2/notifications/configs/$CONFIG_ID" "" "$TOKEN")"
    assert_http "$STATUS" "200" "DELETE canal test"
    echo
  fi
fi

# ---- POST reset notification_test/fr ----------------------------------------

echo "--- POST reset notification_test ---"
echo

echo "18) POST reset — notification_test/fr (était custom)"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/notification_test/fr/reset" "" "$TOKEN")"
assert_http "$STATUS" "200" "POST reset notification_test/fr"
assert_body_field "is_custom = false après reset" ".is_custom" "false"

RESET_SUBJECT="$(jq -r '.subject_template' "$_BODY_FILE")"
if [[ "$RESET_SUBJECT" == "$CUSTOM_SUBJECT" ]]; then
  echo "[KO] sujet non réinitialisé — toujours custom"
  exit 1
fi
echo "[OK] sujet réinitialisé"
echo

echo "19) GET notification_test/fr — vérifier reset persisté"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_test/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_test/fr après reset"
assert_body_field "is_custom = false (persisté)" ".is_custom" "false"
echo

echo "20) POST reset — notification_test/en"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/notification_test/en/reset" "" "$TOKEN")"
assert_http "$STATUS" "200" "POST reset notification_test/en"
assert_body_field "is_custom = false après reset" ".is_custom" "false"
echo

# ---- Compte total des templates ---------------------------------------------

echo "--- Total templates ---"
echo

echo "21) Liste totale des templates — 16 entrées (8 clés × fr/en)"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET /email-templates"
COUNT="$(jq 'length' "$_BODY_FILE")"
assert_equals "$COUNT" "16" "template count = 16"

KEYS_FOUND="$(jq -r '.[].template_key' "$_BODY_FILE" | sort -u | tr '\n' ',')"
for KEY in invitation password_reset email_verification magic_login smtp_test announcement notification_event notification_test; do
  if ! echo "$KEYS_FOUND" | grep -q "$KEY"; then
    echo "[KO] Clé manquante dans la liste : $KEY"
    exit 1
  fi
  echo "[OK] clé $KEY présente"
done
echo

echo "==========================="
echo "Tous les tests sont passés."
echo "==========================="
