from dataclasses import dataclass


@dataclass
class DestinationConfig:
    id: str
    user_id: str

    # Technical destination type.
    # Examples: "synology", "local".
    destination_type: str

    # User-facing profile name.
    # Examples: "NAS maison", "NAS parents", "Local serveur".
    name: str

    is_enabled: bool
    is_default: bool

    config_json: str

    created_at: str
    updated_at: str

    @property
    def destination_name(self) -> str:
        """
        Temporary V2 compatibility alias.

        Old code expects destination_name to contain "synology" or "local".
        New V3 code must use destination_type for logic and name for display.
        """
        return self.destination_type

    @property
    def display_name(self) -> str:
        return self.name
