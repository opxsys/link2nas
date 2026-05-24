from backend.services_v2.user_context import UserContext


def resolve_provider_config(
    provider_factory,
    context: UserContext,
    provider_name: str | None = None,
    provider_config_id: str | None = None,
):
    if provider_factory is None:
        raise RuntimeError("Provider factory is not configured")

    return provider_factory.resolve_provider_config_for_user(
        user_id=context.user_id,
        provider_name=provider_name,
        provider_config_id=provider_config_id,
    )


def resolve_destination_config(
    destination_factory,
    context: UserContext,
    destination_name: str | None = None,
    destination_config_id: str | None = None,
    *,
    allow_none: bool = True,
):
    if not destination_name and not destination_config_id and allow_none:
        return None

    if destination_factory is None:
        raise RuntimeError("Destination factory is not configured")

    return destination_factory.resolve_destination_config_for_user(
        user_id=context.user_id,
        destination_name=destination_name,
        destination_config_id=destination_config_id,
        allow_none=allow_none,
    )
