#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
export ADMIN_API_KEY="${ADMIN_API_KEY:-}"

echo "=== test_v3_smoke — quick, no providers, no SMTP ==="
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
echo

# Preflight: skip gracefully if app not running
reach="$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/v2/me" 2>/dev/null || echo "000")"
if [[ "$reach" != "200" && "$reach" != "401" && "$reach" != "403" ]]; then
  echo "[SKIP] App not reachable at $BASE_URL (HTTP $reach) — start the app first"
  exit 0
fi
echo "[OK] App reachable (HTTP $reach)"
echo

# Obtain shared admin token once; export only ADMIN_API_KEY — never TOKEN, as some
# child scripts treat TOKEN as a user-scoped token and must not see the admin value.
if [[ -n "$ADMIN_API_KEY" ]]; then
  unset TOKEN
elif [[ -n "${TOKEN:-}" ]]; then
  export ADMIN_API_KEY="$TOKEN"
  unset TOKEN
else
  [[ -n "$ADMIN_PASSWORD" ]] || { echo "[KO] ADMIN_PASSWORD is required (no ADMIN_API_KEY or TOKEN set)"; exit 1; }
  _LOGIN="$(curl -s -X POST "$BASE_URL/api/v2/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
  _TOK="$(echo "$_LOGIN" | jq -r '.token // empty')"
  if [[ -z "$_TOK" || "$_TOK" == "null" ]]; then
    echo "[KO] Admin login failed"
    echo "     response: $_LOGIN"
    exit 1
  fi
  export ADMIN_API_KEY="$_TOK"
  echo "[OK] Admin token obtained: ${_TOK:0:8}..."
fi
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


# Smoke is intentionally limited:
# - no real provider
# - no real SMTP
# - no real NAS
# - no notification tests requiring email configuration
#
# test_single_user_mode.sh and test_multi_user_mode.sh are excluded from smoke:
# they require a specific application configuration (LINK2NAS_SINGLE_USER_MODE).
# Run them via a dedicated environment when needed.

run_script "scripts/tests/settings/test_app_settings.sh"
run_script "scripts/tests/auth/test_account_tokens.sh"
run_script "scripts/tests/admin/test_admin_anti_abuse.sh"
run_script "scripts/quality/check_admin_users_routes.sh"
run_script "scripts/tests/qbittorrent/test_qbittorrent_rate_limit.sh"

echo
echo "=== test_v3_smoke: OK ==="
