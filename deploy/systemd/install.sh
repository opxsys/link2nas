#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/link2nas"
VENV_DIR="$APP_DIR/venv"
SYSTEMD_DIR="/etc/systemd/system"

WEB_SERVICE="link2nas-web.service"
SCHED_SERVICE="link2nas-scheduler.service"

echo "=== Link2NAS install ==="

if [[ $EUID -ne 0 ]]; then
  echo "❌ Must be run as root"
  exit 1
fi

if [[ ! -f "$APP_DIR/.env" ]]; then
  echo "❌ $APP_DIR/.env not found"
  echo "➡️  Copy .env.example to .env and configure it first"
  exit 1
fi

echo "✔ .env found"

echo "→ Creating virtualenv (if needed)"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

echo "→ Installing Python dependencies"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "→ Installing systemd services"
cp "$APP_DIR/deploy/$WEB_SERVICE" "$SYSTEMD_DIR/$WEB_SERVICE"
cp "$APP_DIR/deploy/$SCHED_SERVICE" "$SYSTEMD_DIR/$SCHED_SERVICE"

echo "→ Reloading systemd"
systemctl daemon-reload

echo "→ Enabling services"
systemctl enable "$WEB_SERVICE"
systemctl enable "$SCHED_SERVICE"

echo
echo "✔ Installation complete"
echo
echo "Next steps:"
echo "  systemctl start $WEB_SERVICE"
echo "  systemctl start $SCHED_SERVICE"
echo
echo "Check status:"
echo "  systemctl status $WEB_SERVICE"
echo "  systemctl status $SCHED_SERVICE"
