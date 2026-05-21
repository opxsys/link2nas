import { escapeHtml, formatDate } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { isPanelOpen } from "./panel-state.js";
import { resolveTranslatedMessage, formatDestinationStatus } from "./status.js";

export function renderDestinationBlock(job) {
  const resolvedDestinationMessage = resolveTranslatedMessage(
    job.destination_message_key,
    job.destination_message_params,
    job.destination_message
  );

  const destinationStatus = String(job.destination_status || "").trim().toLowerCase();


  const destinationName = String(job.destination_name || job.destination_type || "")
    .trim()
    .toLowerCase();

  const isLocalDestination = destinationName === "local";

  const destinationProgress = Math.max(
    0,
    Math.min(100, Number(job.destination_progress || 0))
  );

  const showDestinationProgress =
    isLocalDestination &&
    (
      destinationStatus === "downloading" ||
      destinationStatus === "queued" ||
      destinationStatus === "sent"
    );

  const destinationMessageClass =
    destinationStatus === "failed" ? "destination-message is-error" : "destination-message";

  const defaultOpen =
    Boolean(job.send_to_destination) ||
    Boolean(job.sent_to_destination) ||
    Boolean(job.destination_status) ||
    Boolean(resolvedDestinationMessage) ||
    Boolean(job.destination_path);

  const destinationOpen = isPanelOpen(job, "destination", defaultOpen);

  return `
    <details class="detail-block collapsible-block" data-panel="destination" ${destinationOpen ? "open" : ""}>
      <summary>${t("destination.title")}</summary>
      <div class="collapsible-content">
        <div class="kv-grid">
          <div class="kv-item"><strong>${t("destination.send")}</strong><div>${job.send_to_destination ? t("destination.yes") : t("destination.no")}</div></div>
          <div class="kv-item"><strong>${t("destination.sent")}</strong><div>${job.sent_to_destination ? t("destination.yes") : t("destination.no")}</div></div>
          <div class="kv-item"><strong>${t("destination.status")}</strong><div>${escapeHtml(formatDestinationStatus(job))}</div></div>
              ${
            showDestinationProgress
              ? `<div class="kv-item"><strong>${t("job.local_progress")}</strong><div>${escapeHtml(String(destinationProgress))}%</div></div>`
              : ``
          }
          <div class="kv-item"><strong>${t("destination.message")}</strong><div class="${destinationMessageClass}">${escapeHtml(resolvedDestinationMessage || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("destination.path")}</strong><div class="code-block">${escapeHtml(job.destination_path || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("destination.last_attempt")}</strong><div>${escapeHtml(formatDate(job.destination_last_attempt))}</div></div>
          <div class="kv-item"><strong>${t("destination.sent_at")}</strong><div>${escapeHtml(formatDate(job.sent_to_destination_at))}</div></div>
        </div>
        ${
          showDestinationProgress
            ? `
              <div class="progress-bar-top progress">
                <span style="width:${destinationProgress}%"></span>
              </div>
            `
            : ``
        }
      </div>
    </details>
  `;
}
