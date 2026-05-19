export const API_BASE = "";
export const JOBS_POLL_MS = 5000;
export const ACTIVE_JOB_POLL_MS = 2000;

export const ACTIVE_STATUSES = new Set([
  "created",
  "queued",
  "starting",
  "started",
  "source_added",
  "waiting_files_selection",
  "downloading",
  "uploading",
  "files_selected",
  "magnet_conversion",
  "compressing",
  "downloaded",
  "ready",
  "partially_ready",
  "torrent_info_updated",
]);