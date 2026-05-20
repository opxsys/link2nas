#!/usr/bin/env bash
set -euo pipefail

echo "=== Link2NAS V2 auth/tokens/invitations wiring inspection ==="

echo
echo "1) Flask routes auth/setup/users/tokens/public"
python3 - <<'PY'
from app import app

for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
    path = str(rule)
    if (
        "auth" in path
        or "setup" in path
        or "users" in path
        or "token" in path
        or "invite" in path
        or "invitation" in path
        or "password" in path
        or "magic" in path
        or "verify" in path
    ):
        print(rule.methods, path)
PY

echo
echo "2) Backend route files"
find backend/routes_v2 -maxdepth 1 -type f | sort | grep -E 'auth|user|token|invite|smtp|setup|public' || true

echo
echo "3) Services related to auth/tokens/email"
find backend/services_v2 -maxdepth 1 -type f | sort | grep -E 'auth|token|smtp|email|user|password|magic|invitation|verification' || true

echo
echo "4) Models related to auth/tokens"
find backend/models -maxdepth 1 -type f | sort | grep -E 'user|token|smtp|session|invitation|verification' || true

echo
echo "5) Repositories related to tokens/users"
find backend/repositories -type f | sort | grep -E 'user|token|smtp|session' || true

echo
echo "6) Grep important keywords"
grep -R "invitation\\|invite\\|password_reset\\|reset password\\|magic\\|email_verification\\|verify email\\|force_password_change\\|account_token\\|public/tokens" -n \
  backend/routes_v2 \
  backend/services_v2 \
  backend/models \
  backend/repositories \
  frontend/js \
  scripts \
  | head -n 300 || true

echo
echo "=== Inspection done ==="
