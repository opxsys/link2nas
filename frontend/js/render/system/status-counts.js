import { escapeHtml } from "../../utils.js";
import { t } from "../../i18n/index.js";

export function renderStatusCounts(statusCounts = {}) {
  const orderedStatuses = [
    "created",
    "queued",
    "source_added",
    "waiting_files_selection",
    "downloading",
    "downloaded",
    "ready",
    "partially_ready",
    "completed",
    "failed",
    "cancelled",
  ];

  const statusClass = {
    failed:          "kv-item-danger",
    completed:       "kv-item-success",
    downloading:     "kv-item-accent",
    ready:           "kv-item-accent",
    partially_ready: "kv-item-accent",
    cancelled:       "kv-item-muted",
  };

  const items = orderedStatuses
    .map((status) => {
      const value = Number(statusCounts?.[status] || 0);
      if (value === 0) return "";
      const extra = statusClass[status] ? ` ${statusClass[status]}` : "";
      return `<div class="kv-item${extra}">
        <strong>${escapeHtml(t(`status.${status}`))}</strong>
        <div>${escapeHtml(String(value))}</div>
      </div>`;
    })
    .filter(Boolean)
    .join("");

  return items || `<p class="muted">${escapeHtml(t("control_center.no_active_statuses"))}</p>`;
}
