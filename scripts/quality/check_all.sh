#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[check_all] Running Python checks..."
scripts/quality/check_python.sh

echo
echo "[check_all] Running frontend JS checks..."
scripts/quality/check_frontend_js.sh

echo
echo "[check_all] Running secret checks..."
scripts/quality/check_secrets.sh

echo
echo "[check_all] Running unit tests..."
scripts/quality/check_unit_tests.sh

echo
echo "[check_all] OK"
