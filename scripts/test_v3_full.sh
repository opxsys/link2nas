#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

echo "=== test_v3_full ==="
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

run_script "scripts/test_v3_sqlite.sh"
run_script "scripts/test_v3_postgres.sh"

echo
echo "=== test_v3_full: OK ==="
