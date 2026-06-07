from __future__ import annotations

from backend.utils.time import utc_now_iso
import uuid

from backend.models.user import User


SINGLE_USER_ID = "00000000-0000-4000-8000-000000000001"

_now = utc_now_iso


class SingleUserService:
    def __init__(self, user_repository, settings) -> None:
        self.user_repository = user_repository
        self.settings = settings

    def _promote_user(self, user: User, timestamp: str) -> User:
        """Ensure a user has the required single-user properties. Returns the user."""
        changed = False

        if user.role != "super_admin":
            user.role = "super_admin"
            changed = True

        if not user.is_active:
            user.is_active = True
            changed = True

        if not user.email_verified_at:
            user.email_verified_at = timestamp
            changed = True

        if getattr(user, "force_password_change", False):
            user.force_password_change = False
            changed = True

        if changed:
            user.updated_at = timestamp
            self.user_repository.update(user)

        return user

    def get_or_create_single_user(self) -> User:
        email = str(
            getattr(self.settings, "LINK2NAS_SINGLE_USER_EMAIL", "")
            or "single-user@link2nas.local"
        ).strip().lower()

        display_name = str(
            getattr(self.settings, "LINK2NAS_SINGLE_USER_DISPLAY_NAME", "")
            or "Single User"
        ).strip() or "Single User"

        timestamp = _now()

        # Canonical single-user (fixed ID) takes priority.
        # Do not overwrite email/display_name from .env after creation —
        # those fields are editable from the UI and stored in DB.
        existing_by_id = self.user_repository.get_by_id(SINGLE_USER_ID)
        if existing_by_id:
            return self._promote_user(existing_by_id, timestamp)

        # No canonical single-user yet. If a user with the configured email
        # already exists (e.g. switching from multi-user to single-user mode),
        # reuse that account rather than failing.
        existing_by_email = self.user_repository.get_by_email(email)
        if existing_by_email:
            return self._promote_user(existing_by_email, timestamp)

        user = User(
            id=SINGLE_USER_ID,
            email=email,
            display_name=display_name,
            role="super_admin",
            is_active=True,
            created_at=timestamp,
            updated_at=timestamp,
            password_hash=None,
            valid_from=None,
            account_expires_at=None,
            email_verified_at=timestamp,
            email_verification_token=str(uuid.uuid4()),
            password_reset_token=None,
            password_reset_sent_at=None,
            last_login_at=None,
            force_password_change=False,
        )

        self.user_repository.create(user)
        return user
