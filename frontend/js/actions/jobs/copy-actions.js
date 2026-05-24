import { state } from "../../state.js";
import { renderJobDetails, forceOpenJobPanel } from "../../render/job-details.js";
import { showAppMessage, copyToClipboard } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { clearCopyFlags } from "./state-helpers.js";

export async function handleCopyJobAction(action, jobId, fileId, { selectJob }) {
  if (action === "copy-download-url") {
    const job = state.selectedJob;

    if (!job?.download_url) {
      showAppMessage(t("messages.no_link_to_copy"), "info");
      return true;
    }

    const ok = await copyToClipboard(job.download_url);

    if (ok) {
      clearCopyFlags(job);
      job._copyDownloadUrlDone = true;
      renderJobDetails(job);
    }

    showAppMessage(
      ok ? t("messages.link_copied") : t("messages.copy_error"),
      ok ? "success" : "error"
    );
    return true;
  }

  if (action === "copy-all-downloads") {
    const job = state.selectedJob;

    const urls = (job.files || [])
      .map((f) => f.download_url)
      .filter(Boolean);

    if (urls.length === 0) {
      showAppMessage(t("messages.no_link_to_copy"), "info");
      return true;
    }

    const ok = await copyToClipboard(urls.join("\n"));

    if (ok) {
      clearCopyFlags(job);
      job._copyAllDownloadsDone = true;
      forceOpenJobPanel(job.id, "files");
      renderJobDetails(job);
    }

    showAppMessage(
      ok ? t("messages.links_copied", { count: urls.length }) : t("messages.copy_error"),
      ok ? "success" : "error"
    );
    return true;
  }

  if (action === "copy-file-url" && fileId != null) {
    const job = state.selectedJob;
    const file = (job.files || []).find((f) => String(f.id) === String(fileId));

    if (!file?.download_url) {
      showAppMessage(t("messages.file_link_unavailable"), "info");
      return true;
    }

    const ok = await copyToClipboard(file.download_url);

    if (ok) {
      clearCopyFlags(job);
      file._copyDone = true;
      forceOpenJobPanel(job.id, "files");
      renderJobDetails(job);
    }

    showAppMessage(
      ok ? t("messages.link_copied") : t("messages.copy_error"),
      ok ? "success" : "error"
    );
    return true;
  }

  return false;
}
