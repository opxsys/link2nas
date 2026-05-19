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

    def get_or_create_single_user(self) -> User:
        email = str(
            getattr(self.settings, "LINK2NAS_SINGLE_USER_EMAIL", "")
            or "single-user@link2nas.local"
        ).strip().lower()

        display_name = str(
            getattr(self.settings, "LINK2NAS_SINGLE_USER_DISPLAY_NAME", "")
            or "Single User"
        ).strip() or "Single User"

        existing_by_email = self.user_repository.get_by_email(email)
        existing_by_id = self.user_repository.get_by_id(SINGLE_USER_ID)

        if existing_by_email and existing_by_email.id != SINGLE_USER_ID:
            raise RuntimeError(
                f"Single-user email already belongs to another account: {email}"
            )

        timestamp = _now()

        if existing_by_id:
            changed = False

            # Do not overwrite email/display_name from .env after creation.
            # In single-user mode, the profile is editable from the UI and stored in DB.
            # LINK2NAS_SINGLE_USER_EMAIL and LINK2NAS_SINGLE_USER_DISPLAY_NAME are only
            # initial bootstrap/fallback values.

            if existing_by_id.role != "super_admin":
                existing_by_id.role = "super_admin"
                changed = True

            if not existing_by_id.is_active:
                existing_by_id.is_active = True
                changed = True

            if not existing_by_id.email_verified_at:
                existing_by_id.email_verified_at = timestamp
                changed = True

            if getattr(existing_by_id, "force_password_change", False):
                existing_by_id.force_password_change = False
                changed = True

            if changed:
                existing_by_id.updated_at = timestamp
                self.user_repository.update(existing_by_id)

            return existing_by_id

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
