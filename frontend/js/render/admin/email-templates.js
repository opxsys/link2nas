import { t } from "../../i18n/index.js";

export function renderEmailTemplatesPanel() {
  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="email-templates" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.email_templates.title")}</h3>
          <p class="muted">${t("admin.email_templates.description")}</p>
        </div>
      </div>

      <div id="admin-email-templates-feedback" hidden></div>

      <div class="email-template-selector">
        <label>
          <span>${t("admin.email_templates.template")}</span>
          <select id="email-template-key-select"></select>
        </label>
        <label>
          <span>${t("admin.email_templates.language")}</span>
          <select id="email-template-lang-select">
            <option value="fr">${t("settings.account.language_fr")}</option>
            <option value="en">${t("settings.account.language_en")}</option>
          </select>
        </label>
        <span id="email-template-custom-badge" class="badge"></span>
      </div>

      <div id="email-template-variables-block" class="detail-block" hidden>
        <h4>${t("admin.email_templates.variables")}</h4>
        <div id="email-template-variables" class="email-template-variables"></div>
      </div>

      <div class="form-grid">
        <label>
          <span>${t("admin.email_templates.subject")}</span>
          <input type="text" id="email-template-subject" />
        </label>
        <label>
          <span>${t("admin.email_templates.body")}</span>
          <textarea id="email-template-body" rows="14"></textarea>
        </label>
      </div>

      <div class="admin-form-actions">
        <button type="button" class="btn btn-primary" id="email-template-save-btn" data-action="email-template-save">
          ${t("admin.email_templates.save")}
        </button>
        <button type="button" class="btn" id="email-template-preview-btn" data-action="email-template-preview">
          ${t("admin.email_templates.preview")}
        </button>
        <button type="button" class="btn btn-danger" id="email-template-reset-btn" data-action="email-template-reset">
          ${t("admin.email_templates.reset")}
        </button>
      </div>

      <div id="email-template-preview-block" hidden>
        <div class="detail-block">
          <h4>${t("admin.email_templates.preview_title")}</h4>
          <div class="email-template-preview-row">
            <strong>${t("admin.email_templates.rendered_subject")}</strong>
            <p id="email-template-preview-subject" class="email-template-preview-subject"></p>
          </div>
          <div class="email-template-preview-row">
            <strong>${t("admin.email_templates.rendered_body")}</strong>
            <pre id="email-template-preview-body" class="email-template-preview-body"></pre>
          </div>
          <details>
            <summary class="muted">${t("admin.email_templates.sample_values")}</summary>
            <pre id="email-template-preview-sample" class="email-template-preview-sample"></pre>
          </details>
        </div>
      </div>
    </section>
  `;
}
