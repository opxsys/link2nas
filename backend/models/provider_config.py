from dataclasses import dataclass


@dataclass
class ProviderConfig:
    id: str
    user_id: str

    # Technical provider type.
    # Examples: "realdebrid", "alldebrid".
    provider_type: str

    # User-facing profile name.
    # Examples: "RealDebrid perso", "RealDebrid backup", "AllDebrid test".
    name: str

    is_enabled: bool
    is_default: bool

    encrypted_api_key: str | None
    account_expires_at: str | None

    created_at: str
    updated_at: str

    @property
    def provider_name(self) -> str:
        """
        Temporary V2 compatibility alias.

        Old code expects provider_name to contain "realdebrid" or "alldebrid".
        New V3 code must use provider_type for logic and name for display.
        """
        return self.provider_type

    @property
    def display_name(self) -> str:
        return self.name
