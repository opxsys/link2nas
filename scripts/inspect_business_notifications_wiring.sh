#!/usr/bin/env bash
set -euo pipefail

echo "=== Link2NAS V2 business notifications wiring inspection ==="

echo
echo "1) Grep notification create_event usage"
grep -R "create_event(" -n \
  backend/routes_v2 \
  backend/services_v2 \
  | grep -v "__pycache__" || true

echo
echo "2) Grep business event names"
grep -R "job\\.\\|provider\\.\\|destination\\." -n \
  backend/routes_v2 \
  backend/services_v2 \
  frontend/js \
  scripts \
  | grep -v "__pycache__" | head -n 300 || true

echo
echo "3) Job service notification references"
grep -n "notification\\|create_event\\|job\\.\\|provider\\.\\|destination\\." backend/services_v2/job_service.py || true

echo
echo "4) Provider runtime/account checks"
grep -R "account\\|expires\\|expiration\\|premium\\|valid_until\\|provider" -n \
  backend/routes_v2/provider_runtime.py \
  backend/routes_v2/providers.py \
  backend/services_v2/providers \
  | grep -v "__pycache__" | head -n 300 || true

echo
echo "5) Destination send/failure paths"
grep -R "destination_status\\|send_to_destination\\|destination\\.failed\\|destination\\.sent" -n \
  backend/services_v2 \
  backend/routes_v2/jobs.py \
  | grep -v "__pycache__" | head -n 300 || true

echo
echo "=== Inspection done ==="
