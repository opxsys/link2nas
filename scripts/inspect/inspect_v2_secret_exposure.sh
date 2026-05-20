#!/usr/bin/env bash
set -euo pipefail

echo "=== Link2NAS V2 secret exposure inspection ==="

echo
echo "1) Grep suspicious API response fields"
grep -R "encrypted_api_key\|api_key\|password\|encrypted_password\|token\|secret" -n \
  backend/routes_v2 \
  backend/services_v2 \
  backend/repositories \
  backend/models \
  | grep -v "__pycache__" \
  | head -n 400 || true

echo
echo "2) Provider serialization"
grep -R "has_api_key\|account_expires_at\|provider_name\|encrypted_api_key\|api_key" -n \
  backend/routes_v2/providers.py \
  backend/services_v2/provider_config_service.py \
  backend/repositories/sqlite/provider_config_repository.py \
  backend/repositories/postgres/provider_config_repository.py \
  backend/models/provider_config.py \
  2>/dev/null || true

echo
echo "3) Destination serialization"
grep -R "password\|encrypted_password\|has_password\|url\|username\|destination_name" -n \
  backend/routes_v2/destinations.py \
  backend/services_v2/destination_config_service.py \
  backend/repositories/sqlite/destination_config_repository.py \
  backend/repositories/postgres/destination_config_repository.py \
  backend/models/destination_config.py \
  2>/dev/null || true

echo
echo "4) SMTP serialization"
grep -R "encrypted_password\|has_password\|password\|serialize_smtp" -n \
  backend/routes_v2/admin_smtp.py \
  backend/repositories/sqlite/smtp_settings_repository.py \
  backend/repositories/postgres/smtp_settings_repository.py \
  backend/models/smtp_settings.py \
  2>/dev/null || true

echo
echo "5) Notification config serialization"
grep -R "_safe_config\|_config_to_public_dict\|token\|headers\|has_token\|has_headers" -n \
  backend/services_v2/notification_service.py \
  backend/routes_v2/notifications.py \
  2>/dev/null || true

echo
echo "6) Public/auth token responses"
grep -R "raw_token\|token_hash\|magic_url\|verification_url\|invitation_url\|reset_url\|token" -n \
  backend/routes_v2/public_tokens.py \
  backend/routes_v2/admin_users.py \
  backend/services_v2/account_token_service.py \
  backend/repositories/sqlite/account_token_repository.py \
  backend/repositories/postgres/account_token_repository.py \
  2>/dev/null || true

echo
echo "=== Inspection done ==="
