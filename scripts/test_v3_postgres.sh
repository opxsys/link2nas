#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
export BASE_URL

export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@test.local}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
export ADMIN_API_KEY="${ADMIN_API_KEY:-}"

export V2_DATABASE_BACKEND="postgres"
export V2_POSTGRES_DSN="${V2_POSTGRES_DSN:-postgresql://link2nas:link2nas_dev_password@127.0.0.1:5432/link2nas_v2}"

unset POSTGRES_DSN
unset TOKEN

echo "=== test_v3_postgres ==="
echo "Backend=$V2_DATABASE_BACKEND"
echo "BASE_URL=$BASE_URL"
echo "ADMIN_EMAIL=$ADMIN_EMAIL"
echo "V2_POSTGRES_DSN set: yes"
echo

scripts/test_v3_full.sh

echo
echo "=== test_v3_postgres: OK ==="