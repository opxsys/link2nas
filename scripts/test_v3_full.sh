#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export BASE_URL

export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
export ADMIN_API_KEY="${ADMIN_API_KEY:-}"

echo "=== test_v3_full ==="
echo "Backend=${V2_DATABASE_BACKEND:-unset}"
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
echo

# Obtain shared admin token once; export only ADMIN_API_KEY — never TOKEN.
if [[ -n "$ADMIN_API_KEY" ]]; then
  unset TOKEN
elif [[ -n "${TOKEN:-}" ]]; then
  export ADMIN_API_KEY="$TOKEN"
  unset TOKEN
else
  [[ -n "$ADMIN_PASSWORD" ]] || {
    echo "[KO] ADMIN_PASSWORD is required (no ADMIN_API_KEY or TOKEN set)"
    exit 1
  }

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

# Ici uniquement les vrais tests, pas les wrappers backend.
run_script "scripts/test_v3_smoke.sh"
run_script "scripts/tests/settings/test_app_settings.sh"
run_script "scripts/tests/settings/test_runtime_settings.sh"
run_script "scripts/tests/auth/test_account_tokens.sh"
run_script "scripts/tests/admin/test_admin_anti_abuse.sh"
run_script "scripts/quality/check_admin_users_routes.sh"
run_script "scripts/tests/qbittorrent/test_qbittorrent_rate_limit.sh"
run_script "scripts/tests/auth/test_app_settings_auth_policy.sh"
run_script "scripts/tests/auth/test_email_verification.sh"
run_script "scripts/tests/admin/test_user_disable.sh"
run_script "scripts/tests/admin/test_user_disabled_connected.sh"
run_script "scripts/tests/admin/test_user_local_space_permission.sh"
run_script "scripts/tests/admin/test_user_public_space.sh"
run_script "scripts/tests/settings/test_session_inactivity_setting.sh"
run_script "scripts/tests/settings/test_cleanup.sh"
run_script "scripts/tests/settings/test_maintenance.sh"
run_script "scripts/tests/notifications/test_notification_schema.sh"
run_script "scripts/tests/notifications/test_notifications.sh"
run_script "scripts/tests/notifications/test_notification_dispatcher.sh"
run_script "scripts/tests/notifications/test_notification_trigger_dedup.sh"
run_script "scripts/tests/notifications/test_notification_links_ready.sh"
run_script "scripts/tests/notifications/test_business_notifications.sh"
run_script "scripts/tests/auth/test_transactional_auth_emails.sh"
run_script "scripts/tests/email/run_email_templates.sh"
run_script "scripts/tests/security/test_v2_rate_limits.sh"
run_script "scripts/tests/security/test_v2_secret_exposure.sh"
run_script "scripts/tests/security/test_system_events.sh"
run_script "scripts/tests/security/test_timeouts.sh"
run_script "scripts/tests/qbittorrent/test_qbittorrent_compat.sh"

echo
echo "=== test_v3_full: OK ==="