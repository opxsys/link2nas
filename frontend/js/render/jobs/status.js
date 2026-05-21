import { escapeHtml } from "../../utils.js";
import { t } from "../../i18n/index.js";

export function resolveTranslatedMessage(key, params, fallback = "") {
  if (key) {
    return t(key, params || {});
  }
  return fallback || "";
}

export function formatDestinationStatus(job) {
  const status = String(job.destination_status || "").trim().toLowerCase();

  const destinationType = String(
    job.destination_type || job.destination_name || ""
  ).trim().toLowerCase();

  if (!status) return t("common.none");

  if (status === "sent") {
    if (destinationType === "local") return t("destination.status.saved_local");
    return t("destination.status.sent");
  }

  if (status === "queued") return t("job.local_status.queued");
  if (status === "downloading") return t("job.local_status.downloading");
  if (status === "cancel_requested") return t("job.local_status.cancel_requested");
  if (status === "cancelled") return t("job.local_status.cancelled");
  if (status === "sending") return t("destination.status.sending");
  if (status === "failed") return t("destination.status.failed");
  if (status === "pending") return t("destination.status.pending");

  return status;
}

export function renderJobMessage(job) {
  const status = String(job.status || "").trim().toLowerCase();
  const hasError = Boolean(job.error_message);

  const message = resolveTranslatedMessage(
    job.last_message_key,
    job.last_message_params,
    job.last_message || job.error_message
  );

  if (!message) return "";
  if (status === "completed" && !hasError) return "";

  return `
    <div class="job-message-banner ${hasError ? "is-error" : "is-info"}">
      ${escapeHtml(message)}
    </div>
  `;
}
