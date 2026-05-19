from dataclasses import dataclass


@dataclass
class Job:
    id: str
    user_id: str

    source_type: str
    source_value: str

    status: str

    # V3 provider profile reference.
    provider_config_id: str | None

    # Snapshots kept on the job for history/display and temporary V2 compatibility.
    # provider_name remains the technical provider type: "realdebrid" | "alldebrid".
    provider_name: str | None
    provider_profile_name: str | None

    provider_resource_id: str | None
    provider_status: str | None
    provider_payload_json: str | None

    # V3 destination profile reference.
    # None means links-only / no destination profile.
    destination_config_id: str | None

    # Snapshots kept on the job for history/display and temporary V2 compatibility.
    # destination_name remains the technical destination type: "synology" | "local" | None.
    destination_name: str | None
    destination_profile_name: str | None

    output_mode: str | None
    output_links_json: str | None
    unrestricted_at: str | None

    error_message: str | None

    created_at: str
    updated_at: str
    started_at: str | None
    completed_at: str | None
    cancelled_at: str | None = None

    send_to_destination: bool = False
    sent_to_destination: bool = False
    sent_to_destination_at: str | None = None
    destination_status: str | None = None
    destination_message: str | None = None
    destination_message_key: str | None = None
    destination_message_params: str | None = None
    destination_last_attempt: str | None = None
    destination_path: str | None = None
    destination_progress: int = 0

    @property
    def provider_type(self) -> str | None:
        return self.provider_name

    @property
    def destination_type(self) -> str | None:
        return self.destination_name
