def resolve_files_to_select(provider_payload: dict) -> str:
    files = provider_payload.get("files") or []

    ids = []

    for index, item in enumerate(files, start=1):
        if isinstance(item, dict):
            file_id = item.get("id") or item.get("file_id") or index
        else:
            file_id = index

        ids.append(str(file_id))

    if ids:
        return ",".join(ids)

    return "all"
