#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

echo "=== test_v3_smoke — quick, no providers, no SMTP ==="
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
[[ -n "$ADMIN_PASSWORD" ]] || { echo "[KO] ADMIN_PASSWORD is required for this runner"; exit 1; }
echo

# Preflight: skip gracefully if app not running
reach="$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/v2/me" 2>/dev/null || echo "000")"
if [[ "$reach" != "200" && "$reach" != "401" && "$reach" != "403" ]]; then
  echo "[SKIP] App not reachable at $BASE_URL (HTTP $reach) — start the app first"
  exit 0
fi
echo "[OK] App reachable (HTTP $reach)"
echo

run_script() {
  local script="$1"
  echo
  echo "================================================================"
  echo "RUN $script"
  echo "================================================================"
  [[ -x "$script" ]] || { echo "[KO] not executable: $script"; exit 1; }
  "$script"
}

# test_single_user_mode.sh et test_multi_user_mode.sh sont exclus du smoke :
# ils supposent une configuration applicative spécifique (LINK2NAS_SINGLE_USER_MODE).
# Les lancer via test_v3_sqlite.sh / test_v3_full.sh dans un environnement dédié.
run_script "scripts/tests/settings/test_app_settings.sh"
run_script "scripts/tests/settings/test_runtime_settings.sh"
run_script "scripts/tests/auth/test_account_tokens.sh"
run_script "scripts/tests/admin/test_admin_anti_abuse.sh"
run_script "scripts/quality/check_admin_users_routes.sh"
run_script "scripts/tests/qbittorrent/test_qbittorrent_rate_limit.sh"

echo
echo "=== test_v3_smoke: OK ==="
