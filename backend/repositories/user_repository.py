from backend.models.user import User


class UserRepository:
    def __init__(self, db):
        self.db = db

    def _row_to_user(self, row) -> User:
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
        )

    def create(self, user: User) -> None:
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    id,
                    email,
                    display_name,

                    password_hash,

                    role,
                    is_active,

                    valid_from,
                    account_expires_at,

                    email_verified_at,
                    email_verification_token,

                    password_reset_token,
                    password_reset_sent_at,

                    last_login_at,

                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.id,
                    user.email,
                    user.display_name,

                    user.password_hash,

                    user.role,
                    int(user.is_active),

                    user.valid_from,
                    user.account_expires_at,

                    user.email_verified_at,
                    user.email_verification_token,

                    user.password_reset_token,
                    user.password_reset_sent_at,

                    user.last_login_at,

                    user.created_at,
                    user.updated_at,
                ),
            )

    def update(self, user: User) -> None:
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET
                    email = ?,
                    display_name = ?,

                    password_hash = ?,

                    role = ?,
                    is_active = ?,

                    valid_from = ?,
                    account_expires_at = ?,

                    email_verified_at = ?,
                    email_verification_token = ?,

                    password_reset_token = ?,
                    password_reset_sent_at = ?,

                    last_login_at = ?,

                    updated_at = ?
                WHERE id = ?
                """,
                (
                    user.email,
                    user.display_name,

                    user.password_hash,

                    user.role,
                    int(user.is_active),

                    user.valid_from,
                    user.account_expires_at,

                    user.email_verified_at,
                    user.email_verification_token,

                    user.password_reset_token,
                    user.password_reset_sent_at,

                    user.last_login_at,

                    user.updated_at,
                    user.id,
                ),
            )

    def delete(self, user_id: str) -> None:
        with self.db.get_connection() as conn:
            conn.execute(
                "DELETE FROM users WHERE id = ?",
                (user_id,),
            )

    def get_by_id(self, user_id: str) -> User | None:
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

        return self._row_to_user(row) if row else None

    def get_by_email(self, email: str) -> User | None:
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE lower(email) = lower(?)",
                (email,),
            ).fetchone()

        return self._row_to_user(row) if row else None

    def list_all(self) -> list[User]:
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM users
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [self._row_to_user(r) for r in rows]