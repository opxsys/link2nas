#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

run_script() {
  local script="$1"
  echo
  echo "================================================================"
  echo "RUN $script"
  echo "================================================================"
  [[ -x "$script" ]] || { echo "[KO] not executable: $script"; exit 1; }
  "$script"
}

echo "=== run_email_templates ==="
run_script "scripts/tests/email/test_email_templates_passe_a.sh"
run_script "scripts/tests/email/test_email_templates_passe_b.sh"
run_script "scripts/tests/email/test_email_templates_passe_c.sh"
run_script "scripts/tests/email/test_email_templates_passe_d.sh"
run_script "scripts/tests/email/test_email_templates_notification_test.sh"
echo
echo "=== run_email_templates: OK ==="
