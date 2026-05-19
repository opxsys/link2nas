#!/usr/bin/env bash
set -euo pipefail

echo "=== Link2NAS V2 notification schema test ==="

SQLITE_DB="${SQLITE_DB:-/tmp/link2nas_notification_schema_test.sqlite3}"
SQLITE_SCHEMA="${SQLITE_SCHEMA:-backend/storage/schema.sql}"

rm -f "$SQLITE_DB"

echo
echo "1) SQLite schema init"
python3 - <<PY
import sqlite3
from pathlib import Path

db_path = Path("$SQLITE_DB")
schema_path = Path("$SQLITE_SCHEMA")

sql = schema_path.read_text(encoding="utf-8")

conn = sqlite3.connect(db_path)
try:
    conn.executescript(sql)
    conn.commit()

    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }

    indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    }

    required_tables = {
        "notification_configs",
        "notification_events",
    }

    required_indexes = {
        "idx_notification_configs_user_id",
        "idx_notification_configs_user_channel",
        "idx_notification_events_user_id",
        "idx_notification_events_status",
        "idx_notification_events_next_retry_at",
        "idx_notification_events_user_status",
        "idx_notification_events_job_id",
    }

    missing_tables = sorted(required_tables - tables)
    missing_indexes = sorted(required_indexes - indexes)

    if missing_tables:
        raise SystemExit(f"[KO] missing SQLite tables: {missing_tables}")

    if missing_indexes:
        raise SystemExit(f"[KO] missing SQLite indexes: {missing_indexes}")

    columns = {
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(notification_events)"
        ).fetchall()
    }

    if "updated_at" not in columns:
        raise SystemExit("[KO] notification_events.updated_at missing")

    print("[OK] SQLite notification tables and indexes")
finally:
    conn.close()
PY

echo
echo "2) PostgreSQL schema file syntax smoke check"
python3 - <<'PY'
from pathlib import Path

schema = Path("backend/storage/schema_postgres.sql").read_text(encoding="utf-8")

required = [
    "CREATE TABLE IF NOT EXISTS notification_configs",
    "CREATE TABLE IF NOT EXISTS notification_events",
    "idx_notification_configs_user_id",
    "idx_notification_configs_user_channel",
    "idx_notification_events_user_id",
    "idx_notification_events_status",
    "idx_notification_events_next_retry_at",
    "idx_notification_events_user_status",
    "idx_notification_events_job_id",
    "updated_at TEXT NOT NULL",
]

missing = [item for item in required if item not in schema]

if missing:
    raise SystemExit(f"[KO] missing PostgreSQL schema fragments: {missing}")

print("[OK] PostgreSQL notification schema fragments present")
PY

echo
echo "=== OK: notification schema workflow passed ==="
