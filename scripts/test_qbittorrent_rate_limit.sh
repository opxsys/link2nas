#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
API_KEY="${API_KEY:-invalid-test-key}"

ENDPOINT="$BASE_URL/qbittorrent/api/v2/torrents/add"

echo "[TEST] qBittorrent compatibility rate-limit"
echo "[TEST] endpoint: $ENDPOINT"
echo "[TEST] API_KEY: ${API_KEY:0:8}..."
echo

for i in 1 2 3 4; do
  echo "[TEST] attempt $i"

  response_file="$(mktemp)"
  headers_file="$(mktemp)"

  status_code="$(
    curl -sS \
      -o "$response_file" \
      -D "$headers_file" \
      -w "%{http_code}" \
      -X POST "$ENDPOINT" \
      -H "X-Api-Key: $API_KEY" \
      -F "urls=magnet:?xt=urn:btih:0000000000000000000000000000000000000000&dn=rate-limit-test"
  )"

  echo "[TEST] HTTP $status_code"
  echo "[TEST] body:"
  cat "$response_file"
  echo

  retry_after="$(grep -i '^Retry-After:' "$headers_file" | awk '{print $2}' | tr -d '\r' || true)"
  if [[ -n "$retry_after" ]]; then
    echo "[TEST] Retry-After: $retry_after"
  fi

  rm -f "$response_file" "$headers_file"
  echo

  sleep 0.2
done

echo "[TEST] done"
