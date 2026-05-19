from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from config import Settings
from backend.storage.db import Database
from backend.storage.postgres_db import PostgresDatabase


def main() -> None:
    settings = Settings()

    if settings.V2_DATABASE_BACKEND == "sqlite":
        db = Database(str(settings.V2_SQLITE_PATH))
        db.init_schema(str(settings.V2_SCHEMA_PATH))
        print(f"SQLite database initialized: {settings.V2_SQLITE_PATH}")
        return

    if settings.V2_DATABASE_BACKEND == "postgres":
        db = PostgresDatabase(settings.V2_POSTGRES_DSN)
        db.init_schema(str(settings.V2_POSTGRES_SCHEMA_PATH))
        print("PostgreSQL database initialized")
        return

    raise RuntimeError(
        f"Unsupported V2_DATABASE_BACKEND: {settings.V2_DATABASE_BACKEND}"
    )


if __name__ == "__main__":
    main()