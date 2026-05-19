from backend.models.user import User


class UserRepository:
    def __init__(self, db):
        self.db = db

    def create(self, user: User) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    id,
                    email,
                    display_name,
                    role,
                    is_active,
                    password_hash,
                    valid_from,
                    account_expires_at,
                    email_verified_at,
                    email_verification_token,
                    password_reset_token,
                    password_reset_sent_at,
                    last_login_at,
                    force_password_change,
                    preferred_language,
                    receive_application_emails,
                    can_use_local_space,
                    ui_theme,
                    created_at,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user.id,
                    user.email,
                    user.display_name,
                    user.role,
                    user.is_active,
                    user.password_hash,
                    user.valid_from,
                    user.account_expires_at,
                    user.email_verified_at,
                    user.email_verification_token,
                    user.password_reset_token,
                    user.password_reset_sent_at,
                    user.last_login_at,
                    user.force_password_change,
                    user.preferred_language,
                    user.receive_application_emails,
                    user.can_use_local_space,
                    user.ui_theme,
                    user.created_at,
                    user.updated_at,
                ),
            )

    def get_by_id(self, user_id: str) -> User | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = %s",
                (user_id,),
            ).fetchone()

        return self._map_row(row)

    def get_by_email(self, email: str) -> User | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE lower(email) = lower(%s)",
                (email,),
            ).fetchone()

        return self._map_row(row)

    def get_by_public_slug(self, slug: str) -> User | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE public_slug = %s",
                (slug,),
            ).fetchone()

        return self._map_row(row)

    def count_users(self) -> int:
        with self.db.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()

        return int(row["count"])

    def list_all(self) -> list[User]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM users
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [self._map_row(row) for row in rows]

    def update(self, user: User) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET
                    email = %s,
                    display_name = %s,
                    role = %s,
                    is_active = %s,
                    password_hash = %s,
                    valid_from = %s,
                    account_expires_at = %s,
                    email_verified_at = %s,
                    email_verification_token = %s,
                    password_reset_token = %s,
                    password_reset_sent_at = %s,
                    last_login_at = %s,
                    force_password_change = %s,
                    preferred_language = %s,
                    receive_application_emails = %s,
                    public_slug = %s,
                    can_use_local_space = %s,
                    ui_theme = %s,
                    updated_at = %s
                WHERE id = %s
                """,
                (
                    user.email,
                    user.display_name,
                    user.role,
                    user.is_active,
                    user.password_hash,
                    user.valid_from,
                    user.account_expires_at,
                    user.email_verified_at,
                    user.email_verification_token,
                    user.password_reset_token,
                    user.password_reset_sent_at,
                    user.last_login_at,
                    user.force_password_change,
                    user.preferred_language,
                    user.receive_application_emails,
                    user.public_slug,
                    user.can_use_local_space,
                    user.ui_theme,
                    user.updated_at,
                    user.id,
                ),
            )

    def delete(self, user_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM users WHERE id = %s",
                (user_id,),
            )

    def _map_row(self, row) -> User | None:
        if row is None:
            return None

        return User(
            id=row["id"],
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            password_hash=row["password_hash"],
            valid_from=row["valid_from"],
            account_expires_at=row["account_expires_at"],
            email_verified_at=row["email_verified_at"],
            email_verification_token=row["email_verification_token"],
            password_reset_token=row["password_reset_token"],
            password_reset_sent_at=row["password_reset_sent_at"],
            last_login_at=row["last_login_at"],
            force_password_change=bool(row["force_password_change"]),
            preferred_language=row["preferred_language"],
            receive_application_emails=bool(row["receive_application_emails"]),
            public_slug=row.get("public_slug"),
            can_use_local_space=bool(row.get("can_use_local_space", False)),
            ui_theme=row.get("ui_theme"),
        )