import { t } from "../../../i18n/index.js";
import { renderDispatcherRuntimeSection } from "./dispatcher.js";
import { renderOrchestratorRuntimeSection } from "./orchestrator.js";
import { renderLocalWorkerRuntimeSection } from "./local-worker.js";

export function renderRuntimeSettingsPanel(runtimeSettings = null) {
  const dispatcher = runtimeSettings?.notifications?.dispatcher || {};
  const orchestrator = runtimeSettings?.jobs?.orchestrator || {};
  const localWorker = runtimeSettings?.downloads?.local_worker || {};

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="runtime" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.tab.runtime")}</h3>
          <p class="muted">${t("admin.runtime.subtitle")}</p>
        </div>

        <span class="badge ${dispatcher.enabled ? "badge-ready" : ""}">
          ${t(dispatcher.enabled ? "admin.runtime.badge_active" : "admin.runtime.badge_partial")}
        </span>
      </div>

      <div id="admin-runtime-feedback" hidden></div>

      <form id="admin-runtime-form" class="form-grid">

        ${renderDispatcherRuntimeSection(dispatcher)}

        ${renderOrchestratorRuntimeSection(orchestrator)}

        ${renderLocalWorkerRuntimeSection(localWorker)}

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">
            ${t("admin.runtime.save")}
          </button>
        </div>
      </form>
    </section>
  `;
}
