import os


def build_user_summary(event_type: str, title: str, message: str, lang: str | None) -> str:
    is_fr = not str(lang or "").lower().startswith("en")

    fr = {
        "job.completed": "Le job est terminé.",
        "job.failed": "Le job a échoué.",
        "job.links_ready": "Les liens directs du job sont disponibles.",
        "destination.sent": "Le job a été envoyé vers la destination.",
        "destination.failed": "L'envoi vers la destination a échoué.",
        "provider.failed": "Le provider a signalé une erreur.",
        "provider.ready": "Le provider a terminé la préparation.",
    }
    en = {
        "job.completed": "The job is complete.",
        "job.failed": "The job failed.",
        "job.links_ready": "Direct links are available for this job.",
        "destination.sent": "The job was sent to the destination.",
        "destination.failed": "Sending the job to the destination failed.",
        "provider.failed": "The provider reported an error.",
        "provider.ready": "The provider finished preparing the job.",
    }

    mapping = fr if is_fr else en
    fallback = "Notification Link2NAS" if is_fr else "Link2NAS notification"
    return mapping.get(str(event_type or "").strip()) or title or message or fallback


def resolve_job_name(provider_payload: dict, job_id: str | None, lang: str | None) -> str:
    filename = str(provider_payload.get("filename") or "").strip()
    if filename:
        return filename

    files = provider_payload.get("files")
    if isinstance(files, list):
        paths = [str(f.get("path") or "").strip() for f in files if isinstance(f, dict)]
        paths = [p for p in paths if p]
        if paths:
            if len(paths) == 1:
                return os.path.basename(paths[0]) or paths[0]
            try:
                common = os.path.commonpath(paths)
            except (ValueError, TypeError):
                common = ""
            if common and common not in (".", ""):
                name = os.path.basename(common)
                return name if name else common
            return os.path.basename(paths[0]) or paths[0]

    if job_id:
        return f"Job {str(job_id)[:8]}"

    is_fr = not str(lang or "").lower().startswith("en")
    return "Système" if is_fr else "System"
