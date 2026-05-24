from backend.models.user import User


def serialize_user(user: User):
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_super_admin": user.role == "super_admin",
        "is_active": user.is_active,
        "valid_from": user.valid_from,
        "account_expires_at": user.account_expires_at,
        "email_verified_at": user.email_verified_at,
        "email_verified": bool(user.email_verified_at),
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "last_login_at": user.last_login_at,
        "preferred_language": user.preferred_language,
        "can_use_local_space": bool(user.can_use_local_space),
    }
