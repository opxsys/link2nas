#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ -x ".venv/bin/python3" ]]; then
  PYTHON=".venv/bin/python3"
else
  PYTHON="python3"
fi

echo "[check_python] Using: $($PYTHON --version)"
echo "[check_python] Running compileall..."
"$PYTHON" -m compileall config.py app.py backend -q
echo "[check_python] OK"
