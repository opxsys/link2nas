#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[check_unit_tests] WARNING: python3 not found; skipping unit tests"
  exit 0
fi

echo "[check_unit_tests] Using: $(python3 --version)"

if [[ ! -d scripts/tests/unit ]]; then
  echo "[check_unit_tests] No unit test directory found; skipping"
  exit 0
fi

python3 -m unittest discover -s scripts/tests/unit -p "test_*.py" -v

echo "[check_unit_tests] OK"
