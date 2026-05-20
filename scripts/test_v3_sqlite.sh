#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export BASE_URL

export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
export ADMIN_API_KEY="${ADMIN_API_KEY:-}"

export V2_DATABASE_BACKEND="sqlite"
unset V2_POSTGRES_DSN
unset POSTGRES_DSN
unset TOKEN

echo "=== test_v3_sqlite ==="
echo "Backend=$V2_DATABASE_BACKEND"
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
echo

scripts/test_v3_full.sh

echo
echo "=== test_v3_sqlite: OK ==="