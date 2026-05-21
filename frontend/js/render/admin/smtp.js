import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

export function renderSmtpSettingsPanel(smtpSettings = null) {
  const settings = smtpSettings || {
    enabled: false,
    host: "",
    port: 587,
    username: "",
    has_password: false,
    from_email: "",
    from_name: "Link2NAS",
    use_tls: true,
    use_ssl: false,
  };

  const smtpTestEnabled = !!(settings.enabled && settings.host && settings.port && settings.from_email);

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="smtp" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.smtp.title")}</h3>
          <p class="muted">${t("admin.smtp.subtitle")}</p>
        </div>

        <span class="badge ${settings.enabled ? "badge-ready" : ""}">
          ${t(settings.enabled ? "admin.smtp.badge_active" : "admin.smtp.badge_disabled")}
        </span>
      </div>

      <div id="admin-smtp-feedback" hidden></div>

      <form id="admin-smtp-form" class="form-grid admin-smtp-form">
        <label class="checkbox-row">
          <input type="checkbox" name="enabled" ${settings.enabled ? "checked" : ""} />
          <span>${t("admin.smtp.enable")}</span>
        </label>

        <div class="admin-form-grid-2">
          <label>
            <span>${t("admin.smtp.host")}</span>
            <input name="host" placeholder="smtp-relay.example.com" value="${html(settings.host || "")}" />
          </label>

          <label>
            <span>${t("admin.smtp.port")}</span>
            <input name="port" type="number" min="1" max="65535" value="${html(settings.port || 587)}" />
          </label>
        </div>

        <div class="admin-form-grid-2">
          <label>
            <span>${t("admin.smtp.username")}</span>
            <input name="username" autocomplete="username" value="${html(settings.username || "")}" />
          </label>

          <label>
            <span>${t("admin.smtp.password")}</span>
            <input name="password" type="password" autocomplete="new-password" placeholder="${settings.has_password ? t("admin.smtp.password_placeholder_set") : t("admin.smtp.password_placeholder_empty")}" />
          </label>
        </div>

        <div class="admin-form-grid-2">
          <label>
            <span>${t("admin.smtp.from_email")}</span>
            <input name="from_email" type="email" placeholder="noreply@example.com" value="${html(settings.from_email || "")}" />
          </label>

          <label>
            <span>${t("admin.smtp.from_name")}</span>
            <input name="from_name" placeholder="Link2NAS" value="${html(settings.from_name || "")}" />
          </label>
        </div>

        <div class="admin-checkbox-grid">
          <label class="checkbox-row">
            <input type="checkbox" name="use_tls" ${settings.use_tls ? "checked" : ""} />
            <span>${t("admin.smtp.use_tls")}</span>
          </label>

          <label class="checkbox-row">
            <input type="checkbox" name="use_ssl" ${settings.use_ssl ? "checked" : ""} />
            <span>${t("admin.smtp.use_ssl")}</span>
          </label>
        </div>

        <div class="admin-smtp-password-hint">
          ${
            settings.has_password
              ? `<span class="badge badge-ready">${t("admin.smtp.password_saved_badge")}</span>`
              : `<span class="badge">${t("admin.smtp.no_password_badge")}</span>`
          }
          <p class="muted">${t("admin.smtp.password_hint")}</p>
        </div>

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">${t("admin.smtp.save")}</button>
          <button type="button" class="btn" data-action="test-admin-smtp"
            ${!smtpTestEnabled ? "disabled" : ""}>${t("admin.smtp.test")}</button>
        </div>
      </form>

      <div class="detail-block">
        <h4>${t("admin.smtp.transactional_title")}</h4>
        <p class="muted">${t("admin.smtp.transactional_desc")}</p>
        <p class="muted">${t("admin.smtp.public_url_moved_hint")}</p>
      </div>
    </section>
  `;
}
