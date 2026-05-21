export function buildActionKey(action, jobId, fileId = null) {
  return fileId != null ? `${action}:${jobId}:${fileId}` : `${action}:${jobId}`;
}

export function normalizeDestinationName(destinationName) {
  const value = String(destinationName || "").trim().toLowerCase();
  return value === "nas" ? "synology" : value;
}
