import { escapeHtml, formatDate, statusBadgeClass } from "../utils.js";
import { t } from "../i18n/index.js";

function getDisplaySourceType(job) {
  if (job.source_type === "magnet" || job.source_type === "torrent_file") {
    return t("jobs.torrent");
  }

  if (job.source_type === "direct_link") {
    return t("jobs.direct");
  }

  return job.source_type || t("common.none");
}

export function renderJobsList(jobs, selectedJobId) {
  const container = document.getElementById("jobs-list");

  if (!jobs.length) {
    container.innerHTML = `<p class="muted">${t("jobs.empty")}</p>`;
    return;
  }

  container.innerHTML = jobs.map((job) => {
    const progress = job.progress ?? 0;
    const displaySourceType = getDisplaySourceType(job);

    return `
      <article class="job-card ${job.id === selectedJobId ? "is-selected" : ""}" data-job-id="${escapeHtml(job.id)}">
        <div class="job-card-header">
          <strong>${escapeHtml(job.filename || displaySourceType)}</strong>
          <span class="${statusBadgeClass(job.status)}">${escapeHtml(job.status)}</span>
        </div>

        <div class="muted code-block">${escapeHtml(job.id)}</div>
        <div class="muted">${escapeHtml(displaySourceType)} • ${escapeHtml(formatDate(job.updated_at))}</div>

        <div class="progress">
          <span style="width:${Number(progress)}%"></span>
        </div>

        <div class="job-card-footer">
          <span>${escapeHtml(String(progress))}%</span>
          <button class="btn" data-action="select" data-job-id="${escapeHtml(job.id)}">
            ${t("common.view")}
          </button>
        </div>
      </article>
    `;
  }).join("");
}