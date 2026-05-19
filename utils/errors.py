from __future__ import annotations


def friendly_error_message(exc: Exception) -> str:
    raw = str(exc)
    msg = raw.lower()

    already_friendly_messages = {
        "job cancelled",
        "provider timeout",
        "invalid api key or premium access required",
        "provider access denied",
        "resource expired or unavailable",
        "too many requests",
        "provider temporarily unavailable",
        "provider unreachable",
        "invalid magnet",
        "invalid torrent source",
        "invalid torrent file",
        "torrent upload failed",
        "torrent too large",
        "torrent could not start downloading",
        "torrent download took too long",
        "files removed from hoster website",
        "torrent processing failed",
        "invalid link",
        "host or link not supported",
        "link unavailable on host website",
        "password protected link",
        "host download limit reached",
        "too many concurrent downloads for this host",
        "could not unlock this link",
        "invalid provider response",
        "invalid nas credentials",
        "nas unreachable",
        "could not create nas destination folder",
        "could not send task to nas",
        "invalid nas destination path",
        "nas error",
    }

    if raw.strip().lower() in already_friendly_messages:
        return raw.strip()

    if "restart temporarily blocked after cancel" in msg:
        return raw

    if "job must be cancelled or failed before restart" in msg:
        return raw

    if "job is cancelled" in msg:
        return "Job cancelled"

    if "timeout" in msg or "timed out" in msg:
        return "Provider timeout"

    if (
        "401" in msg
        or "unauthorized" in msg
        or "bad token" in msg
        or "apikey" in msg
        or "auth_bad_apikey" in msg
        or "auth_missing_apikey" in msg
        or "auth_blocked" in msg
        or "must_be_premium" in msg
        or "magnet_must_be_premium" in msg
        or "account_invalid" in msg
    ):
        return "Invalid API key or premium access required"

    if "403" in msg:
        return "Provider access denied"

    if (
        "404" in msg
        or "unknown_ressource" in msg
        or "magnet_invalid_id" in msg
        or "resource expired" in msg
        or "expired or unavailable" in msg
    ):
        return "Resource expired or unavailable"

    if "429" in msg or "too many requests" in msg or "magnet_too_many_active" in msg or "magnet_too_many" in msg:
        return "Too many requests"

    if (
        "502" in msg
        or "503" in msg
        or "504" in msg
        or "maintenance" in msg
        or "temporarily unavailable" in msg
        or "link_host_unavailable" in msg
        or "link_host_full" in msg
        or "link_temporary_unavailable" in msg
        or "magnet_internal_error" in msg
    ):
        return "Provider temporarily unavailable"

    # NAS / DSM / Download Station / File Station
    if "downloadstation login failed" in msg or "filestation login failed" in msg:
        return "Invalid NAS credentials"

    if (
        "webapi/auth.cgi" in msg
        or "max retries exceeded with url: /webapi/" in msg
        or "no route to host" in msg
        or "dsm timeout" in msg
        or "nas timeout" in msg
    ):
        return "NAS unreachable"

    if "createfolder failed" in msg:
        return "Could not create NAS destination folder"

    if "downloadstation create failed" in msg:
        return "Could not send task to NAS"

    if "nas target folder must be an absolute path" in msg:
        return "Invalid NAS destination path"

    if "downloadstation" in msg or "filestation" in msg or "dsm" in msg:
        return "NAS error"

    # Generic network/provider connectivity
    if (
        "connectionerror" in msg
        or "failed to establish a new connection" in msg
        or "connection refused" in msg
        or "name or service not known" in msg
        or "nodename nor servname provided" in msg
    ):
        return "Provider unreachable"

    if "magnet_invalid_uri" in msg:
        return "Invalid magnet"

    if "torrent_file_invalid" in msg or "magnet_invalid_file" in msg:
        return "Invalid torrent source"

    if "magnet_file_upload_failed" in msg or "magnet_upload_failed" in msg:
        return "Torrent upload failed"

    if "magnet_too_large" in msg or "magnet_magnet_too_big" in msg:
        return "Torrent too large"

    if "magnet_cant_bootstrap" in msg:
        return "Torrent could not start downloading"

    if "magnet_took_too_long" in msg:
        return "Torrent download took too long"

    if "magnet_links_removed" in msg:
        return "Files removed from hoster website"

    if "magnet_processing_failed" in msg:
        return "Torrent processing failed"

    if "bad_link" in msg or "link_is_missing" in msg:
        return "Invalid link"

    if (
        "hoster_unsupported" in msg
        or "link_host_not_supported" in msg
        or "link_not_supported" in msg
    ):
        return "Host or link not supported"

    if "link_down" in msg:
        return "Link unavailable on host website"

    if "link_pass_protected" in msg:
        return "Password protected link"

    if "link_host_limit_reached" in msg:
        return "Host download limit reached"

    if "link_too_many_downloads" in msg:
        return "Too many concurrent downloads for this host"

    if "link_error" in msg:
        return "Could not unlock this link"

    if "json" in msg:
        return "Invalid provider response"

    return "Unexpected provider error"
def is_transient_error(exc: Exception) -> bool:
    msg = str(exc).lower()

    transient_markers = (
        "timeout",
        "timed out",
        "connection reset",
        "connection aborted",
        "temporarily unavailable",
        "temporary failure",
        "failed to establish a new connection",
        "name or service not known",
        "nodename nor servname provided",
        "connection refused",
        "remote disconnected",
        "502",
        "503",
        "504",
        "bad gateway",
        "gateway timeout",
        "service unavailable",
        "too many requests",
        "429",
        "maintenance",
        "link_host_unavailable",
        "link_host_full",
        "link_temporary_unavailable",
        "magnet_internal_error",
    )

    permanent_markers = (
        "401",
        "403",
        "404",
        "unauthorized",
        "forbidden",
        "unknown_ressource",
        "invalid api key",
        "bad token",
        "unsupported",
        "hoster_unsupported",
        "missing download_url",
        "missing file",
        "empty filename",
        "source_type is empty",
        "source_value is empty",
        "job has no torrent_id",
        "job has no debrid_link",
        "file not found",
        "unsupported output_mode",
        "auth_bad_apikey",
        "auth_missing_apikey",
        "auth_blocked",
        "must_be_premium",
        "magnet_must_be_premium",
        "magnet_invalid_uri",
        "magnet_invalid_file",
        "magnet_invalid_id",
        "magnet_too_large",
        "magnet_magnet_too_big",
        "magnet_links_removed",
        "magnet_processing_failed",
        "bad_link",
        "link_host_not_supported",
        "link_not_supported",
        "link_down",
        "link_pass_protected",
        "link_host_limit_reached",
        "link_too_many_downloads",
    )

    if any(marker in msg for marker in permanent_markers):
        return False

    return any(marker in msg for marker in transient_markers)