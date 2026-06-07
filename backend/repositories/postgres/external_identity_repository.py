from backend.models.external_identity import ExternalIdentity


class ExternalIdentityRepository:
    def __init__(self, db):
        self.db = db

    def get_by_issuer_subject(self, issuer: str, subject: str) -> ExternalIdentity | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM external_identities
                WHERE issuer = %s AND subject = %s
                """,
                (issuer, subject),
            ).fetchone()

        if row is None:
            return None

        return self._map_row(row)

    def get_by_user_id(self, user_id: str) -> list[ExternalIdentity]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM external_identities
                WHERE user_id = %s
                ORDER BY linked_at DESC
                """,
                (user_id,),
            ).fetchall()

        return [self._map_row(row) for row in rows]

    def create(self, identity: ExternalIdentity) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO external_identities (
                    id, user_id, provider, issuer, subject,
                    email, linked_at, last_used_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    identity.id,
                    identity.user_id,
                    identity.provider,
                    identity.issuer,
                    identity.subject,
                    identity.email,
                    identity.linked_at,
                    identity.last_used_at,
                ),
            )

    def count_by_issuer(self, issuer: str) -> int:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM external_identities WHERE issuer = %s",
                (issuer,),
            ).fetchone()
        return row[0] if row else 0

    def update_last_used(self, identity_id: str, last_used_at: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE external_identities
                SET last_used_at = %s
                WHERE id = %s
                """,
                (last_used_at, identity_id),
            )

    def _map_row(self, row) -> ExternalIdentity:
        return ExternalIdentity(
            id=row["id"],
            user_id=row["user_id"],
            provider=row["provider"],
            issuer=row["issuer"],
            subject=row["subject"],
            email=row["email"],
            linked_at=row["linked_at"],
            last_used_at=row["last_used_at"],
        )
