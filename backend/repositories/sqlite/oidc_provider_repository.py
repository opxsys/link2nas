from backend.models.oidc_provider import OidcProvider


class OidcProviderRepository:
    def __init__(self, db):
        self.db = db

    def create(self, provider: OidcProvider) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO oidc_providers (
                    id, name, slug, enabled, issuer, client_id,
                    encrypted_client_secret, scopes, button_label,
                    auto_create_users, allowed_domains_json,
                    state_ttl_seconds, exchange_code_ttl_seconds,
                    sort_order, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider.id, provider.name, provider.slug,
                    1 if provider.enabled else 0,
                    provider.issuer, provider.client_id,
                    provider.encrypted_client_secret,
                    provider.scopes, provider.button_label,
                    1 if provider.auto_create_users else 0,
                    provider.allowed_domains_json,
                    provider.state_ttl_seconds,
                    provider.exchange_code_ttl_seconds,
                    provider.sort_order,
                    provider.created_at, provider.updated_at,
                ),
            )

    def get_by_id(self, provider_id: str) -> OidcProvider | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM oidc_providers WHERE id = ?",
                (provider_id,),
            ).fetchone()
        return self._map_row(row) if row else None

    def get_by_slug(self, slug: str) -> OidcProvider | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM oidc_providers WHERE slug = ?",
                (slug,),
            ).fetchone()
        return self._map_row(row) if row else None

    def get_by_issuer(self, issuer: str) -> OidcProvider | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM oidc_providers WHERE issuer = ?",
                (issuer,),
            ).fetchone()
        return self._map_row(row) if row else None

    def list_all(self) -> list[OidcProvider]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM oidc_providers ORDER BY sort_order, created_at",
            ).fetchall()
        return [self._map_row(row) for row in rows]

    def list_enabled(self) -> list[OidcProvider]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM oidc_providers WHERE enabled = 1 ORDER BY sort_order, created_at",
            ).fetchall()
        return [self._map_row(row) for row in rows]

    def update(self, provider: OidcProvider) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE oidc_providers
                SET name = ?, slug = ?, enabled = ?, issuer = ?,
                    client_id = ?, encrypted_client_secret = ?,
                    scopes = ?, button_label = ?,
                    auto_create_users = ?, allowed_domains_json = ?,
                    state_ttl_seconds = ?, exchange_code_ttl_seconds = ?,
                    sort_order = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    provider.name, provider.slug,
                    1 if provider.enabled else 0,
                    provider.issuer, provider.client_id,
                    provider.encrypted_client_secret,
                    provider.scopes, provider.button_label,
                    1 if provider.auto_create_users else 0,
                    provider.allowed_domains_json,
                    provider.state_ttl_seconds,
                    provider.exchange_code_ttl_seconds,
                    provider.sort_order,
                    provider.updated_at,
                    provider.id,
                ),
            )

    def delete(self, provider_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM oidc_providers WHERE id = ?",
                (provider_id,),
            )

    def _map_row(self, row) -> OidcProvider:
        return OidcProvider(
            id=row["id"],
            name=row["name"],
            slug=row["slug"],
            enabled=bool(row["enabled"]),
            issuer=row["issuer"],
            client_id=row["client_id"],
            encrypted_client_secret=row["encrypted_client_secret"],
            scopes=row["scopes"],
            button_label=row["button_label"],
            auto_create_users=bool(row["auto_create_users"]),
            allowed_domains_json=row["allowed_domains_json"],
            state_ttl_seconds=row["state_ttl_seconds"],
            exchange_code_ttl_seconds=row["exchange_code_ttl_seconds"],
            sort_order=row["sort_order"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
