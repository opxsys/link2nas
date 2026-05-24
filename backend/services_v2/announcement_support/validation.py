from backend.services_v2.announcement_support.constants import VALID_TYPES, VALID_SEVERITIES


def validate_announcement_payload(data: dict) -> None:
    if "type" in data and data["type"] not in VALID_TYPES:
        raise ValueError(
            f"Invalid type '{data['type']}'. Must be one of: {', '.join(sorted(VALID_TYPES))}"
        )
    if "severity" in data and data["severity"] not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{data['severity']}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )
