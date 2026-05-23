import { escapeHtml } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { state } from "../../../state.js";
import { buildActionKey } from "../utils.js";

function isActionLoading(action, jobId, fileId = null) {
  return state.currentActionKey === buildActionKey(action, jobId, fileId);
}

function isAnyActionLoading() {
  return Boolean(state.currentActionKey);
}

function getLoadingLabel(action, defaultLabel) {
  const map = {
    start: t("common.starting"),
    refresh: t("common.refreshing"),
    "resync-provider": t("common.resyncing"),
    "select-files": t("common.selecting"),
    unrestrict: t("job.unrestricting"),
    "unrestrict-file": t("job.unrestricting"),
    "send-to-destination": t("job.sending_to_destination"),
    "resend-to-destination": t("job.sending_to_destination"),
    "send-to-other-destination": t("job.sending_to_destination"),
    "cancel-local-download": t("common.cancelling_local"),
    "clone-with-provider": t("job.clone_with_provider_loading"),
    "copy-download-url": t("job.copying_link"),
    "copy-all-downloads": t("job.copying_links"),
    "copy-file-url": t("common.copying"),
    cancel: t("common.cancelling"),
    restart: t("common.restarting"),
    delete: t("common.deleting"),
  };

  return map[action] || defaultLabel;
}

export function renderAsyncButton({ action, jobId, label, fileId = null, extraClass = "", disabled = false }) {
  const loading = isActionLoading(action, jobId, fileId);
  const finalDisabled = disabled || loading;
  const finalLabel = loading ? getLoadingLabel(action, label) : label;
  const classAttr = extraClass ? `btn ${extraClass}` : "btn";

  return `<button class="${classAttr}" data-action="${escapeHtml(action)}" data-job-id="${escapeHtml(jobId)}"${fileId != null ? ` data-file-id="${escapeHtml(fileId)}"` : ""}${finalDisabled ? " disabled" : ""}>${escapeHtml(finalLabel)}</button>`;
}
