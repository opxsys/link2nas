import { selectJobFiles, unrestrictJob, unrestrictJobFile } from "../../api.js";
import { forceOpenJobPanel } from "../../render/job-details.js";
import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";

export async function handleFileJobAction(action, jobId, fileId, { reloadJobs, selectJob }) {
  if (action === "select-files") {
    await selectJobFiles(jobId, "all");
    showAppMessage(t("messages.select_all_done"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "unrestrict") {
    await unrestrictJob(jobId);
    showAppMessage(t("messages.unrestrict_done"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "unrestrict-file" && fileId != null) {
    forceOpenJobPanel(jobId, "files");
    await unrestrictJobFile(jobId, fileId);
    showAppMessage(t("messages.unrestrict_file_done"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  return false;
}
