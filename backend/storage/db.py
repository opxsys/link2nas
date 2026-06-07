import sqlite3
from pathlib import Path


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_schema(self, schema_path: str):
        with self.connect() as conn:
            with open(schema_path, "r", encoding="utf-8") as f:
                conn.executescript(f.read())

    def run_column_migrations(self):
        """Add columns and indexes introduced after initial schema creation."""
        column_migrations = [
            ("users", "public_slug", "ALTER TABLE users ADD COLUMN public_slug TEXT DEFAULT NULL"),
            ("users", "can_use_local_space", "ALTER TABLE users ADD COLUMN can_use_local_space INTEGER NOT NULL DEFAULT 0"),
            ("users", "ui_theme", "ALTER TABLE users ADD COLUMN ui_theme TEXT DEFAULT NULL"),
            ("oidc_states", "provider_id", "ALTER TABLE oidc_states ADD COLUMN provider_id TEXT DEFAULT NULL"),
        ]
        index_migrations = [
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_slug ON users(public_slug) WHERE public_slug IS NOT NULL",
        ]
        with self.connect() as conn:
            for table, column, sql in column_migrations:
                existing = {
                    row[1]
                    for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
                }
                if column not in existing:
                    conn.execute(sql)
            for sql in index_migrations:
                conn.execute(sql)
