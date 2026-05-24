def map_provider_status(provider_status: str | None) -> str:
    status = str(provider_status or "").strip().lower()

    if status in {"queued", "downloading", "magnet_conversion", "uploading"}:
        return "downloading"

    if status == "waiting_files_selection":
        return "waiting_files_selection"

    if status == "downloaded":
        return "downloaded"

    if status in {"error", "dead"}:
        return "failed"

    return "downloading"


ACTION_RULES = {
    "created": ["start", "cancel"],
    "started": ["refresh", "cancel"],
    "downloading": ["refresh", "cancel"],
    "waiting_files_selection": ["refresh", "select_files", "cancel"],
    "downloaded": ["unrestrict", "cancel"],
    "ready": ["send_to_destination", "cancel"],
    "partially_ready": ["send_to_destination", "cancel"],
    "completed": ["resend", "send_to_destination"],
    "failed": ["restart"],
    "cancelled": ["restart"],
}
