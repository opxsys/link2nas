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

echo "=== CI smoke — Docker SQLite ==="

# Generate ephemeral CI secrets using Python stdlib only (no cryptography install needed).
# A valid Fernet key is urlsafe_b64encode(32 random bytes).
CI_FLASK_SECRET="$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")"
CI_FERNET_KEY="$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")"

echo "FLASK_SECRET_KEY:         ${CI_FLASK_SECRET:0:8}..."
echo "V2_SECRET_ENCRYPTION_KEY: ${CI_FERNET_KEY:0:8}..."

# Build .env from sample, replacing the two placeholder values
cp .env.docker.sample .env
sed -i "s|FLASK_SECRET_KEY=CHANGE_ME_long_random_string|FLASK_SECRET_KEY=${CI_FLASK_SECRET}|" .env
sed -i "s|V2_SECRET_ENCRYPTION_KEY=CHANGE_ME_fernet_key|V2_SECRET_ENCRYPTION_KEY=${CI_FERNET_KEY}|" .env

cleanup() {
  local code=$?
  echo "--- cleanup (exit $code) ---"
  if [[ $code -ne 0 ]]; then
    echo "--- Docker logs (tail 150) ---"
    docker compose logs --tail=150 || true
  fi
  docker compose down -v --remove-orphans || true
  rm -f .env
}
trap cleanup EXIT
echo "Ensuring a clean Docker Compose state..."
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build
echo "Docker Compose started."

wait_for_app() {
  local url="$1" max="${2:-60}" i=0 code
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

wait_for_app "http://127.0.0.1:5000/api/v2/setup/status"

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
echo "=== CI smoke — Docker SQLite: OK ==="
