import { t } from "../../i18n/index.js";

export function renderAdminPageHeader({ singleUserMode }) {
  return `
      <div class="section-header admin-page-header">
        <div>
          <h2>${t("admin.page.title")}</h2>
          <p class="muted">
            ${singleUserMode ? t("admin.page.subtitle_single_user") : t("admin.page.subtitle")}
          </p>
        </div>

        ${
          singleUserMode
            ? `<span class="badge badge-warning">${t("settings.account.single_user_title")}</span>`
            : ""
        }
      </div>`;
}

export function renderSingleUserAdminWarning({ singleUserMode }) {
  if (!singleUserMode) return "";

  return `
            <section class="admin-section-card">
              <div class="admin-section-title">
                <div>
                  <h3>${t("admin.users.single_user_warning_title")}</h3>
                  <p class="muted">${t("admin.users.single_user_warning_text")}</p>
                </div>
              </div>
            </section>
          `;
}
