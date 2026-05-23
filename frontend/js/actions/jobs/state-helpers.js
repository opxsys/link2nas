import { getAdminRestartCooldowns } from "../../api.js";
import { state } from "../../state.js";

let restartCooldownsLoaded = false;

export async function ensureRestartCooldownsLoaded(force = false) {
  if (restartCooldownsLoaded && !force) return;

  try {
    const cooldowns = await getAdminRestartCooldowns();
    state.restartCooldowns = cooldowns;
  } catch {
    // Non-admin ou API indisponible : garder les valeurs fallback.
  }

  restartCooldownsLoaded = true;
}

export function buildActionKey(action, jobId, fileId = null) {
  return fileId != null ? `${action}:${jobId}:${fileId}` : `${action}:${jobId}`;
}

export function setCurrentAction(action, jobId, fileId = null) {
  state.currentActionKey = buildActionKey(action, jobId, fileId);
}

export function clearCurrentAction() {
  state.currentActionKey = null;
}

export function clearCopyFlags(job) {
  if (!job) return;

  job._copyDownloadUrlDone = false;
  job._copyAllDownloadsDone = false;

  if (Array.isArray(job.files)) {
    for (const file of job.files) {
      file._copyDone = false;
    }
  }
}

export function isRestartCooldownError(error) {
  const message = String(error?.message || "");
  return /restart temporarily blocked after cancel/i.test(message);
}
