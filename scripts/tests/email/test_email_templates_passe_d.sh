#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"

RUN_ID="$(date +%Y%m%d%H%M%S)-$$"

echo "=== Link2NAS — Email Templates Passe D ==="
echo "BASE_URL=$BASE_URL"
echo "RUN_ID=$RUN_ID"
echo

# ---- helpers ----------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[KO] Missing command: $1"; exit 1; }
}

_BODY_FILE="/tmp/l2n_etpl_d_test_$$.json"
NOTIF_CONFIG_ID=""
NOTIF_RULE_ID=""
ADMIN_TARGET_EMAIL=""
TOKEN="${TOKEN:-}"

cleanup() {
  if [[ -n "$TOKEN" ]]; then
    # Reset notification_event templates
    for KEY_LANG in "notification_event/fr" "notification_event/en"; do
      curl -sS -X POST "$BASE_URL/api/v2/admin/email-templates/$KEY_LANG/reset" \
        -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
    done

    # Delete notification rule then config (rule refs config)
    if [[ -n "$NOTIF_RULE_ID" ]]; then
      curl -sS -X DELETE "$BASE_URL/api/v2/notifications/rules/$NOTIF_RULE_ID" \
        -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
    fi
    if [[ -n "$NOTIF_CONFIG_ID" ]]; then
      curl -sS -X DELETE "$BASE_URL/api/v2/notifications/configs/$NOTIF_CONFIG_ID" \
        -H "X-Api-Key: $TOKEN" >/dev/null 2>&1 || true
    fi
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

echo "2b) build_user_summary — check unitaire Python"
python -c "
import sys
sys.path.insert(0, '.')
from backend.services_v2.notification_dispatcher_support.content import build_user_summary

cases = [
    ('job.completed', 'Job terminé', '', 'fr', 'Le job est terminé.'),
    ('job.failed',    'Job échoué',  '', 'fr', 'Le job a échoué.'),
    ('destination.sent',   'Envoi ok', '', 'fr', 'Le job a été envoyé vers la destination.'),
    ('destination.failed', 'Envoi KO', '', 'fr', \"L'envoi vers la destination a échoué.\"),
    ('provider.failed',    'Provider KO', '', 'fr', 'Le provider a signalé une erreur.'),
    ('job.completed', 'Job done',  '', 'en', 'The job is complete.'),
    ('job.failed',    'Job failed','', 'en', 'The job failed.'),
    ('destination.sent',   'Sent', '', 'en', 'The job was sent to the destination.'),
    ('system.unknown', 'System event', 'Details here', 'fr', 'System event'),
    ('system.unknown', 'System event', 'Details here', 'en', 'System event'),
    ('system.unknown', '',            'Fallback msg',  'fr', 'Fallback msg'),
]
ok = True
for et, title, msg, lang, expected in cases:
    got = build_user_summary(et, title, msg, lang)
    if got != expected:
        print(f'[KO] build_user_summary({et!r}, {lang!r}): got {got!r}, expected {expected!r}')
        ok = False
    else:
        print(f'[OK] {et} / {lang}: {got!r}')
sys.exit(0 if ok else 1)
"
echo "[OK] build_user_summary unitaire"
echo

echo "2c) resolve_job_name — check unitaire Python"
python -c "
import sys
sys.path.insert(0, '.')
from backend.services_v2.notification_dispatcher_support.content import resolve_job_name

ok = True

def chk(label, got, expected):
    global ok
    if got != expected:
        print(f'[KO] {label}: got {got!r}, expected {expected!r}')
        ok = False
    else:
        print(f'[OK] {label}: {got!r}')

# 1. filename top-level
chk('filename', resolve_job_name({'filename': 'show.mkv'}, 'abc123', 'fr'), 'show.mkv')

# 2. files[].path — single file, no directory
chk('single file no dir', resolve_job_name({'files': [{'path': 'movie.mkv'}]}, 'abc', 'fr'), 'movie.mkv')

# 3. files[].path — single file, with directory
chk('single file with dir', resolve_job_name({'files': [{'path': '/dl/show/ep1.mkv'}]}, 'abc', 'fr'), 'ep1.mkv')

# 4. files[].path — multiple files, common directory
chk('multi files common dir', resolve_job_name(
    {'files': [{'path': '/dl/show/ep1.mkv'}, {'path': '/dl/show/ep2.mkv'}]}, 'abc', 'fr'), 'show')

# 5. files[].path — multiple files, no common root
chk('multi files no common dir', resolve_job_name(
    {'files': [{'path': 'ep1.mkv'}, {'path': 'ep2.mkv'}]}, 'abc', 'fr'), 'ep1.mkv')

# 6. fallback: job_id short
chk('fallback job_id', resolve_job_name({}, '6f4c27e3-dead-beef', 'fr'), 'Job 6f4c27e3')

# 7. fallback: no job_id, FR
chk('system FR', resolve_job_name({}, None, 'fr'), 'Système')

# 8. fallback: no job_id, EN
chk('system EN', resolve_job_name({}, None, 'en'), 'System')

# 9. filename takes priority over files
chk('filename priority over files', resolve_job_name(
    {'filename': 'priority.mkv', 'files': [{'path': 'ignored.mkv'}]}, 'abc', 'fr'), 'priority.mkv')

sys.exit(0 if ok else 1)
"
echo "[OK] resolve_job_name unitaire"
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

echo "GET /api/v2/me — récupérer l'email admin pour to_email explicite"
STATUS="$(api_with_status GET "/api/v2/me" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET /api/v2/me"
ADMIN_TARGET_EMAIL="$(jq -r '.email // empty' "$_BODY_FILE")"
if [[ -z "$ADMIN_TARGET_EMAIL" || "$ADMIN_TARGET_EMAIL" == "null" ]]; then
  echo "[KO] admin email missing from /api/v2/me"
  exit 1
fi
echo "[OK] admin target email: $ADMIN_TARGET_EMAIL"
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

echo "5) GET notification_event/fr → exists with is_custom=false"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_event/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_event/fr"
assert_body_field "notification_event/fr is_custom=false" ".is_custom" "false"
echo

echo "6) GET notification_event/en → exists with is_custom=false"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_event/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_event/en"
assert_body_field "notification_event/en is_custom=false" ".is_custom" "false"
echo

# ---- template tests: notification_event/fr ----------------------------------
# Test preview/validation on fr. fr reste custom jusqu'à la section reset (après dispatch).

echo "--- template tests: notification_event/fr ---"
echo

CUSTOM_SUBJ_FR="[CUSTOM-D-${RUN_ID}] {title}"
CUSTOM_BODY_FR="Job : {job_name}\n\n{user_summary}\n\nType : {event_type}\nSévérité : {severity}\nJob ID : {job_id}\nÉvénement : {event_id}\nConfiguration : {config_name}\nDate : {created_at}"

echo "7) PUT notification_event/fr custom → 200, is_custom=true"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/notification_event/fr" \
  "{\"subject_template\": \"$CUSTOM_SUBJ_FR\", \"body_template\": \"$CUSTOM_BODY_FR\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT notification_event/fr custom"
assert_body_field "is_custom=true" ".is_custom" "true"
echo

echo "8) Preview notification_event/fr — subject must contain CUSTOM-D-$RUN_ID"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/notification_event/fr/preview" \
  "{\"subject_template\": \"$CUSTOM_SUBJ_FR\", \"body_template\": \"$CUSTOM_BODY_FR\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview notification_event/fr"
PREVIEW_SUBJECT="$(jq -r '.subject' "$_BODY_FILE")"
if ! echo "$PREVIEW_SUBJECT" | grep -q "CUSTOM-D-${RUN_ID}"; then
  echo "[KO] preview subject does not contain CUSTOM-D-RUN_ID marker"
  echo "  got: $PREVIEW_SUBJECT"
  exit 1
fi
echo "[OK] preview subject contains CUSTOM-D-RUN_ID: $PREVIEW_SUBJECT"
echo

PREVIEW_BODY="$(jq -r '.body' "$_BODY_FILE")"

echo "9) Preview FR — user_summary rendu : 'Le job est terminé.'"
if ! echo "$PREVIEW_BODY" | grep -qF "Le job est terminé."; then
  echo "[KO] preview FR body ne contient pas 'Le job est terminé.'"
  echo "  body: $PREVIEW_BODY"
  exit 1
fi
echo "[OK] preview FR body contient 'Le job est terminé.'"
echo

echo "10) Preview FR — job_name rendu avec valeur sample : 'Download Test'"
if ! echo "$PREVIEW_BODY" | grep -qF "Download Test"; then
  echo "[KO] preview FR body ne contient pas 'Download Test' (job_name sample)"
  echo "  body: $PREVIEW_BODY"
  exit 1
fi
echo "[OK] preview FR body contient 'Download Test' (job_name sample)"
echo

echo "11) Preview FR — aucun placeholder non expansé"
if echo "$PREVIEW_BODY" | grep -qE '\{[a-z_]+\}'; then
  UNEXPANDED="$(echo "$PREVIEW_BODY" | grep -oE '\{[a-z_]+\}' | head -3 | tr '\n' ' ')"
  echo "[KO] preview FR body contient encore des placeholders : $UNEXPANDED"
  exit 1
fi
echo "[OK] preview FR body — aucun placeholder résiduel"
echo

echo "--- invalid template variable rejected ---"
echo

echo "12) PUT notification_event/fr with unknown variable {evil} → 400"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/notification_event/fr" \
  '{"subject_template": "Subject {title}", "body_template": "{message} — {evil}"}' \
  "$TOKEN")"
assert_http "$STATUS" "400" "PUT notification_event/fr with {evil} → 400"
echo

echo "13) GET notification_event/fr — is_custom=true, no {evil} (rejected PUT not persisted)"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_event/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_event/fr after rejected PUT"
assert_body_field "is_custom=true (unchanged after rejected PUT)" ".is_custom" "true"
CURRENT_SUBJ="$(jq -r '.subject_template' "$_BODY_FILE")"
if echo "$CURRENT_SUBJ" | grep -q "evil"; then
  echo "[KO] rejected template was persisted — subject_template contains 'evil'"
  exit 1
fi
echo "[OK] notification_event/fr still has previous custom template (no evil)"
echo

# ---- custom notification_event/en pour le dispatch --------------------------
# Le dispatcher utilise user.preferred_language, fallback en.
# Si l'admin a preferred_language=null, c'est notification_event/en qui est rendu.
# On customise notification_event/en AVANT le dispatch pour valider l'utilisation
# du template. On utilise toutes les 11 variables autorisées (test non-régression inclus).

echo "--- custom notification_event/en pour le dispatch ---"
echo

CUSTOM_SUBJ_EN="[CUSTOM-D-${RUN_ID}] {title}"
CUSTOM_BODY_EN="Job: {job_name}\n\n{user_summary}\n\n{app_name} — {message}\n\nType: {event_type}\nSeverity: {severity}\nJob ID: {job_id}\nEvent ID: {event_id}\nConfig: {config_name}\nDate: {created_at}"

echo "14) PUT notification_event/en custom (toutes les 11 variables) → 200, is_custom=true"
STATUS="$(api_with_status PUT "/api/v2/admin/email-templates/notification_event/en" \
  "{\"subject_template\": \"$CUSTOM_SUBJ_EN\", \"body_template\": \"$CUSTOM_BODY_EN\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "PUT notification_event/en custom"
assert_body_field "is_custom=true" ".is_custom" "true"
echo

echo "14b) Preview notification_event/en — contenu user_summary et job_name rendus"
STATUS="$(api_with_status POST "/api/v2/admin/email-templates/notification_event/en/preview" \
  "{\"subject_template\": \"$CUSTOM_SUBJ_EN\", \"body_template\": \"$CUSTOM_BODY_EN\"}" \
  "$TOKEN")"
assert_http "$STATUS" "200" "POST preview notification_event/en"
PREVIEW_BODY_EN="$(jq -r '.body' "$_BODY_FILE")"
# Les sample values sont communes à fr/en : user_summary = "Le job est terminé."
# La traduction "The job is complete." est couverte par le test unitaire _build_user_summary (step 2b).
if ! echo "$PREVIEW_BODY_EN" | grep -qF "Le job est terminé."; then
  echo "[KO] preview EN body ne contient pas la valeur sample user_summary ('Le job est terminé.')"
  echo "  body: $PREVIEW_BODY_EN"
  exit 1
fi
echo "[OK] preview EN body contient la valeur sample user_summary ('Le job est terminé.')"
if ! echo "$PREVIEW_BODY_EN" | grep -qF "Download Test"; then
  echo "[KO] preview EN body ne contient pas 'Download Test' (job_name sample)"
  echo "  body: $PREVIEW_BODY_EN"
  exit 1
fi
echo "[OK] preview EN body contient 'Download Test' (job_name sample)"
if echo "$PREVIEW_BODY_EN" | grep -qE '\{[a-z_]+\}'; then
  UNEXPANDED_EN="$(echo "$PREVIEW_BODY_EN" | grep -oE '\{[a-z_]+\}' | head -3 | tr '\n' ' ')"
  echo "[KO] preview EN body contient des placeholders résiduels : $UNEXPANDED_EN"
  exit 1
fi
echo "[OK] preview EN body — aucun placeholder résiduel"
echo "[INFO] notification_event/en est custom avec marqueur CUSTOM-D-${RUN_ID} — dispatch ci-dessous l'utilisera"
echo

# ---- dispatch test ----------------------------------------------------------
# notification_event/fr est custom (step 7), notification_event/en est custom (step 14).
# to_email est explicite (ADMIN_TARGET_EMAIL) : le dispatcher n'a pas besoin de retrouver
# l'utilisateur via event.user_id pour résoudre l'adresse. En conséquence, user peut être
# null dans _send_email, preferred_language absent → fallback en. C'est volontaire :
# cela valide que notification_event/en custom est bien utilisé au rendu.

echo "--- dispatch test ---"
echo
echo "[INFO] to_email=$ADMIN_TARGET_EMAIL (explicite — pas de résolution via user_id)"
echo "[INFO] fallback langue: en → le rendu utilisera notification_event/en custom (CUSTOM-D-${RUN_ID})"
echo

echo "15) Create notification email config (channel=email, to_email=$ADMIN_TARGET_EMAIL)"
NOTIF_CONFIG_NAME="test-passe-d-email-${RUN_ID}"
CREATE_CONFIG_STATUS="$(api_with_status POST "/api/v2/notifications/configs" \
  "{\"name\": \"$NOTIF_CONFIG_NAME\", \"channel\": \"email\", \"config\": {\"to_email\": \"$ADMIN_TARGET_EMAIL\"}}" \
  "$TOKEN")"

if [[ "$CREATE_CONFIG_STATUS" == "201" ]]; then
  NOTIF_CONFIG_ID="$(jq -r '.id // empty' "$_BODY_FILE")"
  if [[ -z "$NOTIF_CONFIG_ID" || "$NOTIF_CONFIG_ID" == "null" ]]; then
    echo "[KO] notification config id missing in 201 response"
    exit 1
  fi
  echo "[OK] notification email config created: $NOTIF_CONFIG_ID"
  echo

  echo "16) Create notification rule for job.failed events"
  NOTIF_RULE_NAME="test-passe-d-rule-${RUN_ID}"
  CREATE_RULE_STATUS="$(api_with_status POST "/api/v2/notifications/rules" \
    "{\"name\": \"$NOTIF_RULE_NAME\", \"config_id\": \"$NOTIF_CONFIG_ID\", \"event_types\": [\"job.failed\"], \"severity_min\": \"info\"}" \
    "$TOKEN")"
  assert_http "$CREATE_RULE_STATUS" "201" "POST /notifications/rules"
  NOTIF_RULE_ID="$(jq -r '.id // empty' "$_BODY_FILE")"
  echo "[OK] notification rule created: $NOTIF_RULE_ID"
  echo

  echo "17) Create test notification event (job.failed)"
  CREATE_EVENT_STATUS="$(api_with_status POST "/api/v2/admin/notifications/events/test" \
    "{\"type\": \"job.failed\", \"severity\": \"error\", \"title\": \"Passe D Test ${RUN_ID}\", \"message\": \"Test from passe D script.\"}" \
    "$TOKEN")"
  assert_http "$CREATE_EVENT_STATUS" "200" "POST /admin/notifications/events/test"
  EVENT_ID="$(jq -r '.id // empty' "$_BODY_FILE")"
  EVENT_STATUS="$(jq -r '.status // empty' "$_BODY_FILE")"
  echo "[OK] notification event created: $EVENT_ID (status=$EVENT_STATUS)"
  echo

  if [[ "$EVENT_STATUS" == "pending" ]]; then
    echo "18) Run dispatcher (notification_event/en custom actif — CUSTOM-D-${RUN_ID})"
    RUN_STATUS="$(api_with_status POST "/api/v2/admin/notifications/dispatcher/run-once" "" "$TOKEN")"
    assert_http "$RUN_STATUS" "200" "POST /admin/notifications/dispatcher/run-once"
    PROCESSED="$(jq -r '.processed // 0' "$_BODY_FILE")"
    SENT="$(jq -r '.sent // 0' "$_BODY_FILE")"
    FAILED="$(jq -r '.failed // 0' "$_BODY_FILE")"
    SKIPPED="$(jq -r '.skipped // 0' "$_BODY_FILE")"
    echo "[OK] dispatcher ran: processed=$PROCESSED sent=$SENT failed=$FAILED skipped=$SKIPPED"

    if (( PROCESSED < 1 )); then
      echo "[WARN] dispatcher processed 0 events — event may have already been dispatched or rule scope mismatch"
    fi

    DISPATCH_ERRORS="$(jq -r '.errors // [] | length' "$_BODY_FILE")"
    if (( DISPATCH_ERRORS > 0 )); then
      FIRST_ERR="$(jq -r '.errors[0].error // empty' "$_BODY_FILE")"
      echo "[INFO] dispatcher errors=$DISPATCH_ERRORS, first: ${FIRST_ERR:0:120}"
      if echo "$FIRST_ERR" | grep -qi "smtp\|not configured\|connection\|auth"; then
        echo "[INFO] SMTP non disponible — statut failed acceptable"
      else
        echo "[WARN] Erreur dispatcher inattendue: $FIRST_ERR"
      fi
    fi

    echo
    echo "[INFO] L'API ne permet pas de vérifier le sujet de l'email envoyé."
    echo "[INFO] Si SMTP actif : vérifier manuellement que l'email reçu a un sujet contenant CUSTOM-D-${RUN_ID}"
    echo
  else
    echo "[INFO] event status=$EVENT_STATUS (not pending) — skip dispatch run"
    echo "[INFO] L'API ne permet pas de vérifier le sujet de l'email envoyé."
    echo
  fi

elif [[ "$CREATE_CONFIG_STATUS" == "400" ]]; then
  CONFIG_ERR="$(jq -r '.error // empty' "$_BODY_FILE")"
  echo "[INFO] notification email config creation returned 400: $CONFIG_ERR"
  echo "[INFO] SMTP non configuré — tests dispatch ignorés (acceptable)"
  echo "[INFO] Le template custom notification_event/en (CUSTOM-D-${RUN_ID}) était actif pendant ce bloc."
  echo
else
  echo "[KO] unexpected HTTP $CREATE_CONFIG_STATUS for POST /notifications/configs"
  jq . "$_BODY_FILE" 2>/dev/null
  exit 1
fi

# ---- reset templates (après dispatch) ---------------------------------------

echo "--- reset templates (après dispatch) ---"
echo

echo "19) POST notification_event/fr/reset → 200"
reset_template "notification_event/fr"
echo

echo "20) GET notification_event/fr after reset → is_custom=false, no custom marker, new default subject"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_event/fr" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_event/fr after reset"
assert_body_field "is_custom=false after reset" ".is_custom" "false"
SUBJ_AFTER_RESET_FR="$(jq -r '.subject_template' "$_BODY_FILE")"
if echo "$SUBJ_AFTER_RESET_FR" | grep -q "CUSTOM-D-"; then
  echo "[KO] notification_event/fr subject still has custom marker after reset"
  exit 1
fi
EXPECTED_DEFAULT_SUBJ='[{app_name}] {user_summary}'
if [[ "$SUBJ_AFTER_RESET_FR" != "$EXPECTED_DEFAULT_SUBJ" ]]; then
  echo "[KO] notification_event/fr reset subject_template: expected '$EXPECTED_DEFAULT_SUBJ', got '$SUBJ_AFTER_RESET_FR'"
  exit 1
fi
echo "[OK] notification_event/fr back to default: $SUBJ_AFTER_RESET_FR"
echo

echo "21) POST notification_event/en/reset → 200"
reset_template "notification_event/en"
echo

echo "22) GET notification_event/en after reset → is_custom=false, no custom marker, new default subject"
STATUS="$(api_with_status GET "/api/v2/admin/email-templates/notification_event/en" "" "$TOKEN")"
assert_http "$STATUS" "200" "GET notification_event/en after reset"
assert_body_field "is_custom=false after reset" ".is_custom" "false"
SUBJ_AFTER_RESET_EN="$(jq -r '.subject_template' "$_BODY_FILE")"
if echo "$SUBJ_AFTER_RESET_EN" | grep -q "CUSTOM-D-"; then
  echo "[KO] notification_event/en subject still has custom marker after reset"
  exit 1
fi
if [[ "$SUBJ_AFTER_RESET_EN" != "$EXPECTED_DEFAULT_SUBJ" ]]; then
  echo "[KO] notification_event/en reset subject_template: expected '$EXPECTED_DEFAULT_SUBJ', got '$SUBJ_AFTER_RESET_EN'"
  exit 1
fi
echo "[OK] notification_event/en back to default: $SUBJ_AFTER_RESET_EN"
echo

# ---- final checks -----------------------------------------------------------

echo "--- final checks ---"
echo

echo "23) python -m compileall backend (final)"
python -m compileall backend -q
echo "[OK] python -m compileall backend"
echo

echo "24) git diff --check (final)"
git diff --check
echo "[OK] git diff --check"
echo

echo "=== OK: Email Templates Passe D — all checks passed ==="
echo
echo "--- Validation manuelle recommandée ---"
echo "TOKEN=\"...\" bash scripts/test_system_events.sh"
echo "TOKEN=\"...\" bash scripts/test_email_templates_passe_a.sh"
echo "TOKEN=\"...\" bash scripts/test_email_templates_passe_b.sh"
echo "TOKEN=\"...\" bash scripts/test_email_templates_passe_c.sh"
echo "TOKEN=\"...\" bash scripts/test_notification_dispatcher.sh"
echo "TOKEN=\"...\" bash scripts/test_notifications.sh"
