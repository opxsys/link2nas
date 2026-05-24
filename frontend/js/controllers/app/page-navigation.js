import { state } from "../../state.js";
import { renderJobDetails } from "../../render/job-details.js";
import { loadJobs } from "../../actions/jobs.js";
import { loadSystemInfo } from "../../actions/system.js";
import { renderProwlarrPanel } from "../../render/prowlarr.js";
import { loadSettings } from "../settings-controller.js";
import { loadAdmin } from "../admin-controller.js";
import { loadAnnouncements } from "../announcements-controller.js";

export async function navigateToPage(page) {
  if (page === "jobs") {
    await loadSettings();
    renderJobDetails(state.selectedJob);
    await loadJobs();
  }

  if (page === "prowlarr") {
    renderProwlarrPanel();
  }

  if (page === "control-center") {
    await loadSystemInfo();
  }

  if (page === "settings") {
    await loadSettings();
  }

  if (page === "announcements") {
    await loadAnnouncements();
  }

  if (page === "admin") {
    await loadAdmin();
  }
}
