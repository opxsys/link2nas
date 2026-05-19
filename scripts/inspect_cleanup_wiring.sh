#!/usr/bin/env bash
set -euo pipefail

echo "=== Link2NAS V2 cleanup wiring inspection ==="

echo
echo "1) Flask routes containing cleanup/clean"
python3 - <<'PY'
from app import app

found = False
for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
    path = str(rule)
    if "cleanup" in path.lower() or "clean" in path.lower():
        found = True
        print(rule.methods, path)

if not found:
    print("[WARN] no cleanup/clean routes found")
PY

echo
echo "2) Cleanup service"
if [[ -f backend/services_v2/cleanup_service.py ]]; then
  sed -n '1,260p' backend/services_v2/cleanup_service.py
else
  echo "[WARN] missing backend/services_v2/cleanup_service.py"
fi

echo
echo "3) Backend cleanup references"
grep -R "cleanup\|retention\|run_cleanup\|cleanup_service\|CLEANUP" -n \
  backend/routes_v2 \
  backend/services_v2 \
  backend/repositories \
  config.py \
  app.py \
  2>/dev/null \
  | grep -v "__pycache__" \
  | head -n 300 || true

echo
echo "4) Frontend cleanup references"
grep -R "run-admin-cleanup\|Lancer le nettoyage\|cleanup\|retention\|runAdminCleanup" -n \
  frontend/js \
  2>/dev/null \
  | head -n 300 || true

echo
echo "5) API functions around cleanup"
grep -R "function .*Cleanup\|cleanup" -n frontend/js/api.js 2>/dev/null || true

echo
echo "6) Admin click handlers around cleanup"
grep -R "run-admin-cleanup\|cleanup" -n frontend/js/app.js 2>/dev/null || true

echo
echo "=== Inspection done ==="
