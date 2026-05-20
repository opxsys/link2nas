#!/usr/bin/env bash
set -euo pipefail

# DEPRECATED: use scripts/test_v3_full.sh instead.
echo "[DEPRECATED] test_v2_full.sh — remplacé par scripts/test_v3_full.sh"
echo

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

echo "=== Link2NAS V2 full test runner ==="
echo "Backend=${V2_DATABASE_BACKEND:-sqlite}"
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
[[ -n "$ADMIN_PASSWORD" ]] || { echo "[KO] ADMIN_PASSWORD is required for this runner"; exit 1; }

run_script() {
  local script="$1"

  echo
  echo "================================================================"
  echo "RUN $script"
  echo "================================================================"

  if [[ ! -x "$script" ]]; then
    echo "[KO] script not executable or missing: $script"
    exit 1
  fi

  "$script"
}

run_script "scripts/tests/settings/test_app_settings.sh"
run_script "scripts/tests/auth/test_app_settings_auth_policy.sh"
run_script "scripts/tests/auth/test_account_tokens.sh"
scripts/setup/ensure_smtp_settings.sh
run_script "scripts/tests/auth/test_transactional_auth_emails.sh"
run_script "scripts/tests/settings/test_runtime_settings.sh"
run_script "scripts/tests/settings/test_maintenance.sh"
run_script "scripts/tests/settings/test_cleanup.sh"
run_script "scripts/tests/security/test_system_events.sh"
run_script "scripts/tests/notifications/test_business_notifications.sh"

echo
echo "=== OK: Link2NAS V2 full test runner passed ==="
