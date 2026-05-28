#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# Preflight — abort early with a clear message if a required tool is missing
for _cmd in docker curl jq python3 sed; do
  command -v "$_cmd" >/dev/null 2>&1 || { echo "[KO] required tool not found: $_cmd"; exit 1; }
done

ADMIN_EMAIL="admin@test.local"
ADMIN_PASSWORD="AdminPassword123!"

echo "=== CI smoke — Docker PostgreSQL ==="

# Generate ephemeral CI secrets using Python stdlib only (no cryptography install needed).
# A valid Fernet key is urlsafe_b64encode(32 random bytes).
# The postgres password is pure hex so it is safe in both DSN and sed substitution.
CI_FLASK_SECRET="$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")"
CI_FERNET_KEY="$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")"
CI_PG_PASSWORD="$(python3 -c "import secrets; print(secrets.token_hex(16))")"

echo "FLASK_SECRET_KEY:         ${CI_FLASK_SECRET:0:8}..."
echo "V2_SECRET_ENCRYPTION_KEY: ${CI_FERNET_KEY:0:8}..."
echo "POSTGRES_PASSWORD:        ${CI_PG_PASSWORD:0:8}..."

# Build .env from postgres sample, replacing all three placeholder values.
# CHANGE_ME_postgres_password appears in both V2_POSTGRES_DSN and POSTGRES_PASSWORD lines.
cp .env.docker.postgres.sample .env
sed -i "s|FLASK_SECRET_KEY=CHANGE_ME_long_random_string|FLASK_SECRET_KEY=${CI_FLASK_SECRET}|" .env
sed -i "s|V2_SECRET_ENCRYPTION_KEY=CHANGE_ME_fernet_key|V2_SECRET_ENCRYPTION_KEY=${CI_FERNET_KEY}|" .env
sed -i "s|CHANGE_ME_postgres_password|${CI_PG_PASSWORD}|g" .env

cleanup() {
  local code=$?
  echo "--- cleanup (exit $code) ---"
  if [[ $code -ne 0 ]]; then
    echo "--- Docker logs (tail 150) ---"
    docker compose -f docker-compose.yml -f docker-compose.postgres.yml logs --tail=150 || true
  fi
  docker compose -f docker-compose.yml -f docker-compose.postgres.yml down -v --remove-orphans || true
  rm -f .env
}
trap cleanup EXIT
echo "Ensuring a clean Docker Compose state..."
docker compose -f docker-compose.yml -f docker-compose.postgres.yml down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
echo "Docker Compose (PostgreSQL) started."

wait_for_app() {
  local url="$1" max="${2:-90}" i=0 code
  echo "Waiting for $url ..."
  while [[ $i -lt $max ]]; do
    code="$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)" || code="000"
    if [[ "$code" == "200" ]]; then
      echo "[OK] App reachable (attempt $(( i + 1 )), HTTP $code)"
      return 0
    fi
    i=$(( i + 1 ))
    echo "  (${i}/${max}) HTTP $code — retrying in 5s..."
    sleep 5
  done
  echo "[KO] App did not become ready after $(( max * 5 ))s"
  return 1
}

# PostgreSQL needs extra time on first run: postgres healthcheck start_period (20s)
# + up to 5 retries at 10s each, then web container startup on top.
wait_for_app "http://127.0.0.1:5000/api/v2/setup/status" 90

# Create first admin if setup has not been completed yet
_SETUP="$(curl -s "http://127.0.0.1:5000/api/v2/setup/status")"
if [[ "$(echo "$_SETUP" | jq -r '.setup_required')" == "true" ]]; then
  echo "Creating first admin ($ADMIN_EMAIL)..."
  _HTTP="$(curl -s -o /tmp/ci_setup.json -w "%{http_code}" \
    -X POST "http://127.0.0.1:5000/api/v2/setup/first-admin" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\",\"display_name\":\"CI Admin\"}")"
  if [[ "$_HTTP" != "200" && "$_HTTP" != "201" ]]; then
    echo "[KO] Setup failed (HTTP $_HTTP)"
    jq 'del(.token)' /tmp/ci_setup.json 2>/dev/null || cat /tmp/ci_setup.json || true
    exit 1
  fi
  echo "[OK] First admin created (HTTP $_HTTP)"
else
  echo "[INFO] Setup not required — admin already exists"
fi

export BASE_URL="http://127.0.0.1:5000"
export ADMIN_EMAIL
export ADMIN_PASSWORD

bash scripts/test_v3_smoke.sh

echo
echo "=== CI smoke — Docker PostgreSQL: OK ==="
