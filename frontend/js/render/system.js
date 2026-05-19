import { formatDate, escapeHtml } from "../utils.js";
import { t } from "../i18n/index.js";

function getProviderStatus(system) {
  if (!system || !system.premium || !system.expiration) {
    return {
      dotClass: "rd-dot-neutral",
      tooltip: t("provider.unavailable_or_non_premium"),
    };
  }

  const now = new Date();
  const expiration = new Date(system.expiration);

  if (Number.isNaN(expiration.getTime())) {
    return {
      dotClass: "rd-dot-neutral",
      tooltip: t("provider.unknown_expiration"),
    };
  }

  const diffMs = expiration.getTime() - now.getTime();
  const daysLeft = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

  let dotClass = "rd-dot-success";

  if (daysLeft <= 7) {
    dotClass = "rd-dot-danger";
  } else if (daysLeft <= 15) {
    dotClass = "rd-dot-warning";
  }

  const providerName = system.provider || "provider";

  const tooltip =
    daysLeft <= 0
      ? t("provider.expired_on", {
          provider: providerName,
          date: formatDate(system.expiration),
        })
      : t("provider.expires_on", {
          provider: providerName,
          date: formatDate(system.expiration),
          days: daysLeft,
        });

  return {
    dotClass,
    tooltip,
  };
}

function formatProviderName(providerName) {
  const value = String(providerName || "").trim().toLowerCase();

  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";

  return "-";
}

function formatDestination(value) {
  const v = String(value || "").toLowerCase();

  if (v === "synology" || v === "nas") return "NAS Synology";

  if (v === "local") return "Local";

  return "-";
}

function renderStatusCounts(statusCounts = {}) {
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

function renderRuntimeServices(runtimeInfo) {
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