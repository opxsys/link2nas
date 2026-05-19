#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"

echo "=== Link2NAS V2 full test runner ==="
echo "Backend=${V2_DATABASE_BACKEND:-sqlite}"
echo "BASE_URL=$BASE_URL"

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

run_script "./scripts/test_app_settings.sh"
run_script "./scripts/test_app_settings_auth_policy.sh"
run_script "./scripts/test_account_tokens.sh"
./scripts/ensure_smtp_settings.sh
run_script "./scripts/test_transactional_auth_emails.sh"
run_script "./scripts/test_runtime_settings.sh"
run_script "./scripts/test_maintenance.sh"
run_script "./scripts/test_cleanup.sh"
run_script "./scripts/test_system_events.sh"
run_script "./scripts/test_business_notifications.sh"

echo
echo "=== OK: Link2NAS V2 full test runner passed ==="
