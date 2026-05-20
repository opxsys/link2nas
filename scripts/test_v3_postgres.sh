#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export V2_DATABASE_BACKEND="postgres"
BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

echo "=== test_v3_postgres ==="
echo "Backend=postgres"
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
[[ -n "$ADMIN_PASSWORD" ]] || { echo "[KO] ADMIN_PASSWORD is required for this runner"; exit 1; }
echo

scripts/test_v3_sqlite.sh

echo
echo "=== test_v3_postgres: OK ==="
