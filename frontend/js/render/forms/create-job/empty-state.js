import { t } from "../../../i18n/index.js";

export function renderCreateJobNoProviderState(container) {
  document.querySelector(".content-grid")?.setAttribute("hidden", "hidden");

  container.innerHTML = `
    <div class="section-header">
      <h2>${t("form.create_jobs")}</h2>
    </div>

    <div class="empty-state">
      <strong>${t("form.no_provider")}</strong>
      <p class="muted">${t("form.no_provider_hint")}</p>
    </div>
  `;
}
