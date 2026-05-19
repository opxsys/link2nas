import { escapeHtml, formatDate, statusBadgeClass, formatJobStatus } from "../utils.js";
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

function renderDestinationBadge(job) {
  if (job.destination_status === "sending") {
    return `<span class="badge badge-warning">${t("destination.badge")}</span>`;
  }

  if (job.sent_to_destination || job.destination_status === "sent") {
    return `<span class="badge badge-success">${t("destination.sent_badge")}</span>`;
  }

  if (job.destination_status === "failed") {
    return `<span class="badge badge-danger">${t("destination.error_badge")}</span>`;
  }

  if (job.send_to_destination) {
    return `<span class="badge">${t("destination.badge")}</span>`;
  }

  return ``;
}

export function renderJobsList(jobs, selectedJobId) {
  const container = document.getElementById("jobs-list");

  if (!jobs.length) {
    container.innerHTML = `
      <div class="empty-state">
        <strong>${t("jobs.empty")}</strong>
        <p class="muted">${t("jobs.empty_hint")}</p>
      </div>
    `;
    return;
  }

  container.innerHTML = jobs.map((job) => {
    const progress = job.progress ?? (job.status === "completed" ? 100 : 0);
    const clampedProgress = Math.max(0, Math.min(100, Number(progress) || 0));
    const title = job.filename || job.source_value || job.source_type;
    const sourceType = getDisplaySourceType(job);
    const badge = renderDestinationBadge(job);

    return `
      <article
        class="job-card ${job.id === selectedJobId ? "is-selected" : ""}"
        data-job-id="${escapeHtml(job.id)}"
        style="--job-progress: ${clampedProgress}%"
      >
        <div class="job-card-progress"></div>

        <div class="job-card-content">
          <div class="job-card-header">
            <strong class="job-card-title">${escapeHtml(title)}</strong>
          </div>

          <div class="job-card-meta">
            <span class="${statusBadgeClass(job.status)}">${escapeHtml(formatJobStatus(job.status))}</span>
            ${badge}
          </div>

          <div class="muted job-card-subtitle">
            ${escapeHtml(sourceType)} • ${escapeHtml(formatDate(job.updated_at))}
          </div>

          <div class="job-card-footer">
            <span>${escapeHtml(String(clampedProgress))}%</span>
            <div class="inline-actions">
              <button class="btn btn-ghost-danger" data-action="delete" data-job-id="${escapeHtml(job.id)}">
                ${t("common.delete")}
              </button>
            </div>
          </div>
        </div>
      </article>
    `;
  }).join("");
}