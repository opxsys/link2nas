from backend.models.identity_proxy_config import IdentityProxyConfig


class IdentityProxyConfigRepository:
    def __init__(self, db):
        self.db = db

    def create(self, config: IdentityProxyConfig) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO identity_proxy_configs (
                    id, name, provider_type, enabled, label,
                    auto_login, auto_create_users,
                    allowed_domains_json, config_json,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    config.id, config.name, config.provider_type,
                    1 if config.enabled else 0,
                    config.label,
                    1 if config.auto_login else 0,
                    1 if config.auto_create_users else 0,
                    config.allowed_domains_json,
                    config.config_json,
                    config.created_at, config.updated_at,
                ),
            )

    def get_by_id(self, config_id: str) -> IdentityProxyConfig | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM identity_proxy_configs WHERE id = ?",
                (config_id,),
            ).fetchone()
        return self._map(row) if row else None

    def get_first(self) -> IdentityProxyConfig | None:
        """Returns the single active config, deterministically by created_at asc."""
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM identity_proxy_configs ORDER BY created_at ASC LIMIT 1",
            ).fetchone()
        return self._map(row) if row else None

    def list_all(self) -> list[IdentityProxyConfig]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM identity_proxy_configs ORDER BY created_at ASC",
            ).fetchall()
        return [self._map(r) for r in rows]

    def update(self, config: IdentityProxyConfig) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE identity_proxy_configs
                SET name = ?, provider_type = ?, enabled = ?, label = ?,
                    auto_login = ?, auto_create_users = ?,
                    allowed_domains_json = ?, config_json = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    config.name, config.provider_type,
                    1 if config.enabled else 0,
                    config.label,
                    1 if config.auto_login else 0,
                    1 if config.auto_create_users else 0,
                    config.allowed_domains_json,
                    config.config_json,
                    config.updated_at,
                    config.id,
                ),
            )

    def delete(self, config_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM identity_proxy_configs WHERE id = ?",
                (config_id,),
            )

    def _map(self, row) -> IdentityProxyConfig:
        return IdentityProxyConfig(
            id=row["id"],
            name=row["name"],
            provider_type=row["provider_type"],
            enabled=bool(row["enabled"]),
            label=row["label"],
            auto_login=bool(row["auto_login"]),
            auto_create_users=bool(row["auto_create_users"]),
            allowed_domains_json=row["allowed_domains_json"],
            config_json=row["config_json"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
