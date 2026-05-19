import psycopg
from psycopg.rows import dict_row


class PostgresDatabase:
    def __init__(self, dsn: str):
        if not dsn:
            raise ValueError("V2_POSTGRES_DSN is required")
        self.dsn = dsn

    def connect(self):
        return psycopg.connect(
            self.dsn,
            row_factory=dict_row,
        )

    def init_schema(self, schema_path: str):
        with self.connect() as conn:
            with conn.cursor() as cur:
                with open(schema_path, "r", encoding="utf-8") as f:
                    cur.execute(f.read())
            conn.commit()
