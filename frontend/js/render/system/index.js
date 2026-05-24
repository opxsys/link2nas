import { formatDate, escapeHtml } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { getProviderStatus, formatProviderName, formatDestination } from "./provider.js";
import { renderStatusCounts } from "./status-counts.js";
import { renderRuntimeServices } from "./runtime-services.js";

export function renderSystemPanel(system, controlCenter, runtimeInfo = null) {
  const slot = document.getElementById("rd-status-slot");
  const panel = document.getElementById("system-panel");

  if (!panel) return;

  if (!system) {
    const tooltip = t("provider.unavailable");

  if (slot) {
    slot.innerHTML = `
      <span class="rd-indicator" title="${tooltip}" aria-label="${tooltip}">
        <span class="rd-dot rd-dot-neutral"></span>
      </span>
    `;
  }

    panel.innerHTML = `<p class="muted">${escapeHtml(t("provider.unavailable"))}</p>`;
    return;
  }

  const status = getProviderStatus(system);

  if (slot) {
    slot.innerHTML = `
      <span class="rd-indicator" title="${status.tooltip}" aria-label="${status.tooltip}">
        <span class="rd-dot ${status.dotClass}"></span>
      </span>
    `;
  }

  const queue = controlCenter?.queue || {};
  const workersNames = Array.isArray(queue.workers_names) && queue.workers_names.length
    ? queue.workers_names.join(", ")
    : t("common.none");

  panel.innerHTML = `
    <div class="section-header">
      <h2>${escapeHtml(t("control_center.title"))}</h2>
      <span class="muted">${escapeHtml(formatDate(controlCenter?.generated_at))}</span>
    </div>

    <div class="detail-block detail-block-first">
      <h3>${escapeHtml(t("control_center.provider"))}</h3>
      <div class="cc-provider-strip">
        <span class="meta-pill">${escapeHtml(formatProviderName(system.provider))}</span>
        <span class="meta-pill">${escapeHtml(t("control_center.destination"))}: ${escapeHtml(String(formatDestination(controlCenter?.destination_type) || "-"))}</span>
        <span class="meta-pill">${escapeHtml(t("control_center.provider_expiration"))}: ${escapeHtml(formatDate(system.expiration))}</span>
      </div>
    </div>

    <div class="detail-block">
      <h3>${escapeHtml(t("control_center.queue"))}</h3>
      <div class="kv-grid">
        <div class="kv-item"><strong>${escapeHtml(t("control_center.queue_pending"))}</strong><div>${escapeHtml(String(queue.pending_count || 0))}</div></div>
        <div class="kv-item"><strong>${escapeHtml(t("control_center.queue_started"))}</strong><div>${escapeHtml(String(queue.started_count || 0))}</div></div>
        <div class="kv-item${queue.failed_count > 0 ? " kv-item-danger" : ""}"><strong>${escapeHtml(t("control_center.queue_failed"))}</strong><div>${escapeHtml(String(queue.failed_count || 0))}</div></div>
        <div class="kv-item"><strong>${escapeHtml(t("control_center.queue_scheduled"))}</strong><div>${escapeHtml(String(queue.scheduled_count || 0))}</div></div>
      </div>
    </div>

    <div class="detail-block">
      <h3>${escapeHtml(t("control_center.workers"))}</h3>
      ${queue.workers_total
        ? `<div class="kv-grid">
            <div class="kv-item"><strong>${escapeHtml(t("control_center.workers_total"))}</strong><div>${escapeHtml(String(queue.workers_total))}</div></div>
            <div class="kv-item"><strong>${escapeHtml(t("control_center.workers_busy"))}</strong><div>${escapeHtml(String(queue.workers_busy || 0))}</div></div>
            <div class="kv-item"><strong>${escapeHtml(t("control_center.workers_idle"))}</strong><div>${escapeHtml(String(queue.workers_idle || 0))}</div></div>
          </div>`
        : `<p class="muted">${escapeHtml(t("control_center.no_workers_detected"))}</p>`}
    </div>

    <div class="detail-block">
      <h3>${escapeHtml(t("control_center.jobs"))}</h3>
      <div class="kv-grid">
        <div class="kv-item"><strong>${escapeHtml(t("control_center.jobs_total"))}</strong><div>${escapeHtml(String(controlCenter?.jobs_total || 0))}</div></div>
        <div class="kv-item"><strong>${escapeHtml(t("control_center.jobs_active"))}</strong><div>${escapeHtml(String(controlCenter?.jobs_active || 0))}</div></div>
        <div class="kv-item"><strong>${escapeHtml(t("control_center.jobs_destination_pending"))}</strong><div>${escapeHtml(String(controlCenter?.jobs_with_destination_pending || 0))}</div></div>
      </div>

      <div class="kv-grid kv-grid-spaced">
        ${renderStatusCounts(controlCenter?.status_counts || {})}
      </div>
    </div>

    ${renderRuntimeServices(runtimeInfo)}
  `;
}
