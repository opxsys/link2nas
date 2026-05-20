#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== test_quality ==="
scripts/quality/check_all.sh
echo
echo "=== test_quality: OK ==="
