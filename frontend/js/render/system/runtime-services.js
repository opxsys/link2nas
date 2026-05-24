import { formatDate, escapeHtml } from "../../utils.js";
import { t } from "../../i18n/index.js";

export function renderRuntimeServices(runtimeInfo) {
  if (!runtimeInfo) return "";

  const orchestrator = runtimeInfo?.jobs?.orchestrator || {};
  const dispatcher = runtimeInfo?.notifications?.dispatcher || {};
  const localWorker = runtimeInfo?.downloads?.local_worker || {};

  function badge(enabled) {
    return enabled
      ? `<span class="meta-pill is-success">${escapeHtml(t("control_center.runtime_enabled"))}</span>`
      : `<span class="meta-pill is-muted">${escapeHtml(t("control_center.runtime_disabled"))}</span>`;
  }

  function detail(label, value) {
    return `<div class="cc-runtime-card-detail"><span class="cc-runtime-label">${escapeHtml(label)}</span> ${escapeHtml(String(value))}</div>`;
  }

  const orchestratorCard = `
    <div class="cc-runtime-card">
      <div class="cc-runtime-card-title">
        <strong>${escapeHtml(t("control_center.runtime_orchestrator"))}</strong>
        ${badge(orchestrator.enabled)}
      </div>
      ${detail(t("control_center.runtime_interval"), `${orchestrator.interval_seconds ?? "-"}s`)}
      ${detail(t("control_center.runtime_max_jobs"), orchestrator.max_jobs_per_run ?? "-")}
    </div>`;

  const dispatcherCard = `
    <div class="cc-runtime-card">
      <div class="cc-runtime-card-title">
        <strong>${escapeHtml(t("control_center.runtime_dispatcher"))}</strong>
        ${badge(dispatcher.enabled)}
      </div>
      ${detail(t("control_center.runtime_interval"), `${dispatcher.interval_seconds ?? "-"}s`)}
      ${detail(t("control_center.runtime_limit"), dispatcher.limit ?? "-")}
      ${dispatcher.last_run_at ? detail(t("control_center.runtime_last_run"), formatDate(dispatcher.last_run_at)) : ""}
      ${dispatcher.last_error ? detail(t("control_center.runtime_last_error"), dispatcher.last_error) : ""}
    </div>`;

  const localWorkerCard = `
    <div class="cc-runtime-card">
      <div class="cc-runtime-card-title">
        <strong>${escapeHtml(t("control_center.runtime_local_worker"))}</strong>
        ${badge(localWorker.enabled)}
      </div>
      ${detail(t("control_center.runtime_interval"), `${localWorker.poll_interval_seconds ?? "-"}s`)}
      ${detail(t("control_center.runtime_max_concurrent"), localWorker.max_concurrent_downloads ?? "-")}
    </div>`;

  return `
    <div class="detail-block">
      <h3>${escapeHtml(t("control_center.runtime_services"))}</h3>
      <div class="cc-runtime-grid">
        ${orchestratorCard}
        ${dispatcherCard}
        ${localWorkerCard}
      </div>
    </div>`;
}
