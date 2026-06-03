#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:5000}"
API_KEY="${API_KEY:-${TOKEN:-}}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERREUR: commande manquante: $1"
    exit 1
  }
}

need curl
need jq

if [[ -z "$API_KEY" ]]; then
  echo "ERREUR: API_KEY manquant."
  echo
  echo "Utilisation :"
  echo "  API_KEY='ton_token_admin' BASE='http://127.0.0.1:5000' ./scripts/check_next_dashboard.sh"
  echo
  echo "Tu peux aussi utiliser TOKEN=... si c'est déjà ta variable habituelle."
  exit 1
fi

api_get() {
  local url="$1"
  curl -s "$url" \
    -H "X-Api-Key: $API_KEY" \
    -H "Accept: application/json"
}

echo "[1/5] Control-center..."
CONTROL="$(api_get "$BASE/api/v2/system/control-center")"

if ! echo "$CONTROL" | jq empty >/dev/null 2>&1; then
  echo "ERREUR: /api/v2/system/control-center ne retourne pas du JSON valide:"
  echo "$CONTROL"
  exit 1
fi

echo "[2/5] Jobs..."
RAW_JOBS="$(api_get "$BASE/api/v2/jobs")"

if ! echo "$RAW_JOBS" | jq empty >/dev/null 2>&1; then
  echo "ERREUR: /api/v2/jobs ne retourne pas du JSON valide:"
  echo "$RAW_JOBS"
  exit 1
fi

echo "[DEBUG] Forme de /api/v2/jobs:"
echo "$RAW_JOBS" | jq -r '
  if type == "array" then
    "array"
  elif type == "object" then
    "object keys: " + ((keys // []) | join(", "))
  else
    type
  end
'

JOBS="$(
  echo "$RAW_JOBS" | jq '
    if type == "array" then
      .
    elif type == "object" and (.jobs | type == "array") then
      .jobs
    elif type == "object" and (.items | type == "array") then
      .items
    elif type == "object" and (.data | type == "array") then
      .data
    else
      []
    end
  '
)"

if echo "$RAW_JOBS" | jq -e 'type == "object" and has("error")' >/dev/null; then
  echo "ERREUR API /api/v2/jobs:"
  echo "$RAW_JOBS" | jq .
  exit 1
fi

echo "[3/5] Providers / destinations..."
PROVIDERS="$(api_get "$BASE/api/v2/providers")"
DESTINATIONS="$(api_get "$BASE/api/v2/destinations")"

echo "[4/5] Maintenance storage..."
MAINT_STATUS="$(
  curl -s -o /tmp/link2nas_maintenance.json -w "%{http_code}" \
    "$BASE/api/v2/admin/maintenance/status" \
    -H "X-Api-Key: $API_KEY" \
    -H "Accept: application/json"
)"

echo "[5/5] Résumé Dashboard attendu"
echo

TODAY="$(date +%Y-%m-%d)"

echo "Control-center:"
echo "$CONTROL" | jq '
  (.status_counts // {}) as $s |
  {
    active_jobs: (.jobs_active // 0),
    waiting_current_dashboard_formula: (($s.queued // 0) + ($s.created // 0)),
    waiting_safer_formula: (($s.queued // 0) + ($s.created // 0) + ($s.waiting // 0) + ($s.starting // 0) + ($s.pending // 0)),
    status_counts: $s
  }
'

echo
echo "Jobs today:"
echo "$JOBS" | jq --arg today "$TODAY" '
  {
    total_jobs_visible_to_api: length,
    completed_today: [
      .[] | select((.completed_at // "") | startswith($today))
    ] | length,
    failed_today_approx: [
      .[] | select((.status // "") == "failed" and ((.updated_at // "") | startswith($today)))
    ] | length
  }
'

echo
echo "Default provider/destination:"
echo "Provider:"
echo "$PROVIDERS" | jq '
  if type == "array" then
    [ .[] | select(.is_enabled == true) ] as $enabled |
    ($enabled[] | select(.is_default == true)) // ($enabled[0] // null)
  else
    .
  end
'

echo "Destination:"
echo "$DESTINATIONS" | jq '
  if type == "array" then
    [ .[] | select(.is_enabled == true) ] as $enabled |
    ($enabled[] | select(.is_default == true)) // ($enabled[0] // null)
  else
    .
  end
'

echo
echo "Recent jobs, top 10:"
echo "$JOBS" | jq -r '
  sort_by(.updated_at // .created_at // "") | reverse | .[:10][] |
  [
    (.status // "-"),
    (.provider_profile_name // .provider_name // .provider_type // "-"),
    (.destination_profile_name // .destination_name // .destination_type // "-"),
    (.updated_at // .created_at // "-"),
    (.filename // .source_value // .id // "-")
  ] | @tsv
'

echo
echo "Maintenance:"
if [[ "$MAINT_STATUS" == "200" ]]; then
  jq '.disk' /tmp/link2nas_maintenance.json
else
  echo "Maintenance inaccessible: HTTP $MAINT_STATUS"
  echo "Normal si la clé n'est pas Super Admin."
  cat /tmp/link2nas_maintenance.json
  echo
fi
