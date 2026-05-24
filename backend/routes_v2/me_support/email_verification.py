from backend.utils.email_templates import build_email_verification_email


def request_email_verification_for_user(
    user_id,
    user_repo,
    token_service,
    smtp_service,
    app_settings,
    email_template_service,
    settings,
    now_func,
):
    user = user_repo.get_by_id(user_id)

    if not user:
        return {"error": "User not found"}, 404

    if user.email_verified_at:
        return {"ok": True, "message": "Email already verified"}, 200

    if not smtp_service or not smtp_service.is_email_sending_available():
        return {"error": "Email sending is not configured."}, 503

    token, raw_token = token_service.create_token(
        user_id=user.id,
        token_type="email_verification",
        created_by_user_id=user.id,
        ttl_hours=app_settings.get_email_verification_ttl_hours(),
    )

    verification_url = token_service.build_email_verification_url(raw_token)

    app_name = app_settings.get_effective_app_name(
        env_fallback=getattr(settings, "APP_NAME", "")
    )

    try:
        if email_template_service:
            subject, body = email_template_service.render(
                "email_verification", user.preferred_language,
                app_name=app_name, url=verification_url, expires_at=token.expires_at,
            )
        else:
            subject, body = build_email_verification_email(
                user.preferred_language, verification_url, token.expires_at, app_name=app_name
            )
        smtp_service.send_email(to_email=user.email, subject=subject, body=body)
    except Exception as exc:
        return {"ok": False, "error": f"Email verification failed: {exc}"}, 502

    user.email_verification_token = None
    user.updated_at = now_func()
    user_repo.update(user)

    return {
        "ok": True,
        "message": f"Email verification sent to {user.email}",
        "expires_at": token.expires_at,
        "verification_url": verification_url,
    }, 200
