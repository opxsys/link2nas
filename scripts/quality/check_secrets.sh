#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if command -v gitleaks >/dev/null 2>&1; then
  echo "[check_secrets] Running gitleaks..."
  gitleaks detect --source . --config .gitleaks.toml --verbose
else
  echo "[check_secrets] WARNING: gitleaks not installed; skipping gitleaks scan"
fi

echo "[check_secrets] Running defensive grep for manual review..."

PATTERN='RD_API_KEY|REALDEBRID_TOKEN|ALLDEBRID|SYNO_PASSWORD|SYNOLOGY_PASSWORD|SMTP_PASSWORD|MAILJET|BREVO|PRIVATE_KEY|SECRET_KEY|V2_SECRET_ENCRYPTION_KEY|TOKEN|API_KEY'

set +e
grep -RInE "$PATTERN" . \
  --exclude-dir=.git \
  --exclude-dir=.venv \
  --exclude-dir=node_modules \
  --exclude-dir=__pycache__ \
  --exclude-dir=.pytest_cache \
  --exclude="*.pyc" \
  --exclude="*.pyo" \
  --exclude=".env" \
  --exclude="*.log" \
  --exclude="*.sqlite" \
  --exclude="*.sqlite3" \
  --exclude="*.db"
GREP_STATUS=$?
set -e

if [[ "$GREP_STATUS" -eq 0 ]]; then
  echo
  echo "[check_secrets] Review the matches above. Variable names and placeholders are expected; real secrets are not."
elif [[ "$GREP_STATUS" -eq 1 ]]; then
  echo "[check_secrets] No defensive grep matches found"
else
  echo "[check_secrets] grep failed with status $GREP_STATUS"
  exit "$GREP_STATUS"
fi

echo "[check_secrets] OK"
