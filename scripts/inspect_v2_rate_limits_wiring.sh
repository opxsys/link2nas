#!/usr/bin/env bash
set -euo pipefail

echo "=== Link2NAS V2 rate limits wiring inspection ==="

check() {
  local file="$1"
  local pattern="$2"

  if grep -q "$pattern" "$file"; then
    echo "[OK] $file contains $pattern"
  else
    echo "[KO] $file missing $pattern"
    exit 1
  fi
}

test -f backend/services_v2/rate_limit_service.py || { echo "[KO] missing rate_limit_service.py"; exit 1; }

check config.py "V2_RATE_LIMIT_ENABLED"
check config.py "V2_RATE_LIMIT_LOGIN_MAX"
check config.py "V2_RATE_LIMIT_MAGIC_LOGIN_MAX"
check config.py "V2_RATE_LIMIT_TOKEN_STATUS_MAX"
check config.py "V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX"
check config.py "V2_RATE_LIMIT_EMAIL_REQUEST_MAX"

check app.py "RateLimitService"
check app.py "RATE_LIMIT_SERVICE_V2"

check backend/routes_v2/auth.py "rate_limit_response"
check backend/routes_v2/public_tokens.py "token_status"
check backend/routes_v2/public_tokens.py "magic_login_request"
check backend/routes_v2/public_tokens.py "password_reset_confirm"
check backend/routes_v2/public_tokens.py "invitation_accept"
check backend/routes_v2/public_tokens.py "email_verification_confirm"

check backend/routes_v2/me.py "email_verification_request"
check backend/routes_v2/me.py "me_password_change"

check backend/routes_v2/admin_users.py "admin_invitation_email"
check backend/routes_v2/admin_users.py "admin_password_reset_email"

python3 -m py_compile   backend/services_v2/rate_limit_service.py   backend/routes_v2/auth.py   backend/routes_v2/public_tokens.py   backend/routes_v2/me.py   backend/routes_v2/admin_users.py   app.py   config.py

echo "=== OK: rate limits wiring inspection passed ==="
