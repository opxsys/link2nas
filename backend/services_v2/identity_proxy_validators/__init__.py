from backend.services_v2.identity_proxy_validators.base import (
    IdentityProxyConfigError,
    IdentityProxyValidator,
)
from backend.services_v2.identity_proxy_validators.cloudflare_access import (
    CloudflareAccessValidator,
)

_REGISTRY: dict[str, type[IdentityProxyValidator]] = {
    "cloudflare_access": CloudflareAccessValidator,
}

SUPPORTED_PROVIDER_TYPES: list[str] = list(_REGISTRY.keys())


def get_identity_proxy_validator(provider_type: str) -> IdentityProxyValidator:
    cls = _REGISTRY.get(provider_type)
    if cls is None:
        raise IdentityProxyConfigError(
            f"Unsupported identity proxy provider type: {provider_type!r}"
        )
    return cls()
