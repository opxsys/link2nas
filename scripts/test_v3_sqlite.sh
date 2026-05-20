#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export V2_DATABASE_BACKEND="${V2_DATABASE_BACKEND:-sqlite}"
BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

echo "=== test_v3_sqlite ==="
echo "Backend=$V2_DATABASE_BACKEND"
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
[[ -n "$ADMIN_PASSWORD" ]] || { echo "[KO] ADMIN_PASSWORD is required for this runner"; exit 1; }
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

# --- Smoke ---
run_script "scripts/test_v3_smoke.sh"

# --- Auth ---
run_script "scripts/tests/auth/test_app_settings_auth_policy.sh"
run_script "scripts/tests/auth/test_email_verification.sh"

# --- Admin ---
run_script "scripts/tests/admin/test_user_disable.sh"
run_script "scripts/tests/admin/test_user_disabled_connected.sh"
run_script "scripts/tests/admin/test_user_local_space_permission.sh"
run_script "scripts/tests/admin/test_user_public_space.sh"

# --- Settings ---
run_script "scripts/tests/settings/test_session_inactivity_setting.sh"
run_script "scripts/tests/settings/test_cleanup.sh"
run_script "scripts/tests/settings/test_maintenance.sh"

# --- Notifications ---
run_script "scripts/tests/notifications/test_notification_schema.sh"
run_script "scripts/tests/notifications/test_notifications.sh"
run_script "scripts/tests/notifications/test_notification_dispatcher.sh"
run_script "scripts/tests/notifications/test_notification_trigger_dedup.sh"
run_script "scripts/tests/notifications/test_notification_links_ready.sh"
run_script "scripts/tests/notifications/test_business_notifications.sh"

# --- Email (transactional, no live SMTP required) ---
run_script "scripts/setup/ensure_smtp_settings.sh"
run_script "scripts/tests/auth/test_transactional_auth_emails.sh"
run_script "scripts/tests/email/run_email_templates.sh"

# --- Security ---
run_script "scripts/tests/security/test_v2_rate_limits.sh"
run_script "scripts/tests/security/test_v2_secret_exposure.sh"
run_script "scripts/tests/security/test_system_events.sh"
run_script "scripts/tests/security/test_timeouts.sh"

# --- qBittorrent ---
run_script "scripts/tests/qbittorrent/test_qbittorrent_compat.sh"

echo
echo "=== test_v3_sqlite: OK ==="
