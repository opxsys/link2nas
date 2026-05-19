#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "[check_frontend_js] WARNING: node not installed; skipping JS syntax check"
  exit 0
fi

echo "[check_frontend_js] Using: $(node --version)"

mapfile -d '' JS_FILES < <(find frontend/js -name "*.js" -print0)

if [[ "${#JS_FILES[@]}" -eq 0 ]]; then
  echo "[check_frontend_js] No JS files found"
  exit 0
fi

for file in "${JS_FILES[@]}"; do
  node --check "$file" >/dev/null
done

echo "[check_frontend_js] OK (${#JS_FILES[@]} files checked)"
