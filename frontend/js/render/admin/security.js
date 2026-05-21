import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

export function renderSecuritySettingsPanel(securitySettings = null) {
  const tokenTtl = securitySettings?.token_ttl || {};
  const passwordPolicy = securitySettings?.password_policy || {};

  const invitationTtlHours = tokenTtl.invitation_ttl_hours ?? 48;
  const passwordResetTtlHours = tokenTtl.password_reset_ttl_hours ?? 2;
  const magicLoginTtlMinutes = tokenTtl.magic_login_ttl_minutes ?? 15;
  const emailVerificationTtlHours = tokenTtl.email_verification_ttl_hours ?? 24;
  const sessionInactivityMinutes = tokenTtl.session_inactivity_minutes ?? 30;

  const minLength = passwordPolicy.min_length ?? 10;
  const requireUppercase = Boolean(passwordPolicy.require_uppercase);
  const requireLowercase = Boolean(passwordPolicy.require_lowercase);
  const requireNumber = Boolean(passwordPolicy.require_number);
  const requireSpecial = Boolean(passwordPolicy.require_special);

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="security" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.security.title")}</h3>
          <p class="muted">${t("admin.security.subtitle")}</p>
        </div>
        <span class="badge badge-ready">${t("admin.security.configured")}</span>
      </div>

      <div id="admin-security-feedback" hidden></div>

      <form id="admin-security-form" class="form-grid">

        <div class="detail-block">
          <h4>${t("admin.security.group_public_links")}</h4>
          <p class="muted">${t("admin.security.group_public_links_hint")}</p>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.security.invitation_ttl_hours")}</span>
              <div class="security-input-row">
                <input name="invitation_ttl_hours" type="number" min="1" max="336" value="${html(invitationTtlHours)}" required />
                <span class="security-input-unit">${t("admin.security.unit_hours")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.security.password_reset_ttl_hours")}</span>
              <div class="security-input-row">
                <input name="password_reset_ttl_hours" type="number" min="1" max="24" value="${html(passwordResetTtlHours)}" required />
                <span class="security-input-unit">${t("admin.security.unit_hours")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.security.magic_login_ttl_minutes")}</span>
              <div class="security-input-row">
                <input name="magic_login_ttl_minutes" type="number" min="5" max="120" value="${html(magicLoginTtlMinutes)}" required />
                <span class="security-input-unit">${t("admin.security.unit_minutes")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.security.email_verification_ttl_hours")}</span>
              <div class="security-input-row">
                <input name="email_verification_ttl_hours" type="number" min="1" max="168" value="${html(emailVerificationTtlHours)}" required />
                <span class="security-input-unit">${t("admin.security.unit_hours")}</span>
              </div>
            </label>
          </div>
        </div>

        <div class="detail-block">
          <h4>${t("admin.security.group_session")}</h4>
          <p class="muted">${t("admin.security.group_session_hint")}</p>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.security.session_inactivity_minutes")}</span>
              <div class="security-input-row">
                <input name="session_inactivity_minutes" type="number" min="5" max="1440" value="${html(sessionInactivityMinutes)}" required />
                <span class="security-input-unit">${t("admin.security.unit_minutes")}</span>
              </div>
            </label>
          </div>
        </div>

        <div class="detail-block">
          <h4>${t("admin.security.group_password_policy")}</h4>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.security.min_length")}</span>
              <div class="security-input-row">
                <input name="min_length" type="number" min="8" max="128" value="${html(minLength)}" required />
              </div>
            </label>
          </div>

          <div class="security-checkbox-grid">
            <label class="checkbox-row">
              <input type="checkbox" name="require_uppercase" ${requireUppercase ? "checked" : ""} />
              <span>${t("admin.security.require_uppercase")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="require_lowercase" ${requireLowercase ? "checked" : ""} />
              <span>${t("admin.security.require_lowercase")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="require_number" ${requireNumber ? "checked" : ""} />
              <span>${t("admin.security.require_number")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="require_special" ${requireSpecial ? "checked" : ""} />
              <span>${t("admin.security.require_special")}</span>
            </label>
          </div>
        </div>

        <div class="security-form-footer">
          <button type="submit" class="btn btn-primary">${t("admin.security.save")}</button>
        </div>
      </form>

      <div class="detail-block" style="margin-top:1.5rem">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.5rem">
          <div>
            <h4>${t("admin.security.anti_abuse.title")}</h4>
            <p class="muted">${t("admin.security.anti_abuse.subtitle")}</p>
          </div>
          <div style="display:flex;gap:0.5rem">
            <button type="button" class="btn btn-secondary" data-action="refresh-anti-abuse">
              ${t("admin.security.anti_abuse.refresh")}
            </button>
            <button type="button" class="btn btn-danger" data-action="reset-anti-abuse-all">
              ${t("admin.security.anti_abuse.reset_all")}
            </button>
          </div>
        </div>
        <div id="admin-anti-abuse-feedback" hidden></div>
        <div id="admin-anti-abuse-content">
          <p class="muted">${t("admin.security.anti_abuse.loading")}</p>
        </div>
      </div>
    </section>
  `;
}
