from backend.services_v2.providers.alldebrid_client import AllDebridClient
from backend.services_v2.providers.alldebrid_provider import AllDebridProvider
from backend.services_v2.providers.base import Provider
from backend.services_v2.providers.realdebrid_client import RealDebridClient
from backend.services_v2.providers.realdebrid_provider import RealDebridProvider

PROVIDER_KEYS: frozenset[str] = frozenset({"realdebrid", "alldebrid"})

PROVIDER_DISPLAY_NAMES: dict[str, str] = {
    "realdebrid": "Real-Debrid",
    "alldebrid": "AllDebrid",
}


def build_provider(provider_type: str, token: str, settings) -> Provider:
    if provider_type == "realdebrid":
        client = RealDebridClient(
            base_url=settings.REALDEBRID_BASE_URL,
            token=token,
            timeout=settings.REALDEBRID_TIMEOUT,
        )
        return RealDebridProvider(client)

    if provider_type == "alldebrid":
        client = AllDebridClient(
            base_url=settings.ALLDEBRID_BASE_URL,
            token=token,
            timeout=settings.ALLDEBRID_TIMEOUT,
        )
        return AllDebridProvider(client)

    raise ValueError(f"Unknown provider type: {provider_type}")
