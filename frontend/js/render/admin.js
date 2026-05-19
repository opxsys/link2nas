import { formatDate } from "../utils.js";
import { t } from "../i18n/index.js";

function html(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function toInputDateTime(value) {
  if (!value) return "";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";

  const pad = (n) => String(n).padStart(2, "0");

  return [
    date.getFullYear(),
    "-",
    pad(date.getMonth() + 1),
    "-",
    pad(date.getDate()),
    "T",
    pad(date.getHours()),
    ":",
    pad(date.getMinutes()),
  ].join("");
}

function renderStatusBadge(label, variant = "") {
  return `<span class="badge ${variant ? `badge-${variant}` : ""}">${html(label)}</span>`;
}

function renderComingSoonCard(title, description) {
  return `
    <article class="admin-placeholder-card">
      <div>
        <h4>${html(title)}</h4>
        <p class="muted">${html(description)}</p>
      </div>
      <span class="badge">À venir</span>
    </article>
  `;
}

function renderUserCard(u, emailAvailable = true) {
  const isActive = Boolean(u.is_active);
  const isSuperAdmin = Boolean(u.is_super_admin);
  const isEmailVerified = Boolean(u.email_verified);
  const canUseLocalSpace = Boolean(u.can_use_local_space);

  return `
    <article class="admin-user-card" data-user-id="${html(u.id)}">
      <div class="admin-user-main">
        <div class="admin-user-header">
          <div class="admin-user-identity">
            <strong class="admin-user-email">${html(u.email)}</strong>
            <span class="muted">${html(u.display_name || t("admin.users.no_display_name"))}</span>
          </div>

          <div class="admin-user-badges">
            ${renderStatusBadge(isActive ? t("admin.users.badge_active") : t("admin.users.badge_disabled"), isActive ? "ready" : "failed")}
            ${isSuperAdmin ? renderStatusBadge(t("admin.users.badge_super_admin"), "premium") : renderStatusBadge(t("admin.users.badge_user"))}
            ${renderStatusBadge(isEmailVerified ? t("admin.users.badge_email_verified") : t("admin.users.badge_email_unverified"), isEmailVerified ? "ready" : "failed")}
            ${canUseLocalSpace ? renderStatusBadge(t("admin.users.badge_local_space"), "ready") : ""}
          </div>
        </div>

        <div class="admin-user-meta">
          <div>
            <span class="muted">${t("admin.users.meta_valid_from")}</span>
            <strong>${u.valid_from ? html(formatDate(u.valid_from)) : "—"}</strong>
          </div>
          <div>
            <span class="muted">${t("admin.users.meta_expires")}</span>
            <strong>${u.account_expires_at ? html(formatDate(u.account_expires_at)) : "—"}</strong>
          </div>
          <div>
            <span class="muted">${t("admin.users.meta_last_login")}</span>
            <strong>${u.last_login_at ? html(formatDate(u.last_login_at)) : "—"}</strong>
          </div>
        </div>

      </div>

      <div class="admin-user-actions">
        <div class="admin-action-group">
          <span class="admin-action-label">${t("admin.users.action_group_account")}</span>

          <button class="btn admin-user-edit-toggle" data-action="toggle-user-edit" data-id="${html(u.id)}">
            ${t("admin.users.edit_summary")}
          </button>

          ${
            isActive
              ? `<button class="btn" data-action="disable-user" data-id="${html(u.id)}">${t("admin.users.btn_disable")}</button>`
              : `<button class="btn" data-action="enable-user" data-id="${html(u.id)}">${t("admin.users.btn_enable")}</button>`
          }

          ${
            !isEmailVerified
              ? `<button class="btn" data-action="verify-user-email" data-id="${html(u.id)}">${t("admin.users.btn_verify_email")}</button>`
              : ""
          }
        </div>

        <div class="admin-action-group">
          <span class="admin-action-label">${t("admin.users.action_group_access")}</span>

          <button class="btn" data-action="create-user-invitation" data-id="${html(u.id)}">
            ${t("admin.users.btn_copy_invitation")}
          </button>

          <button class="btn" data-action="send-user-invitation-email" data-id="${html(u.id)}"
            ${!emailAvailable ? `disabled title="${t("email.smtp_configure_hint")}"` : ""}>
            ${t("admin.users.btn_send_invitation")}
          </button>

          <button class="btn" data-action="create-user-password-reset-link" data-id="${html(u.id)}">
            ${t("admin.users.btn_copy_reset")}
          </button>

          <button class="btn" data-action="send-user-password-reset-email" data-id="${html(u.id)}"
            ${!emailAvailable ? `disabled title="${t("email.smtp_configure_hint")}"` : ""}>
            ${t("admin.users.btn_send_reset")}
          </button>
        </div>

        <div class="admin-action-group admin-action-group--danger">
          <span class="admin-action-label">${t("admin.users.action_group_danger")}</span>
          <button class="btn btn-danger" data-action="delete-user" data-id="${html(u.id)}">
            ${t("admin.users.btn_delete")}
          </button>
        </div>
      </div>

      <div class="admin-user-edit-content" hidden>
        <form class="form-grid user-edit-form" data-user-id="${html(u.id)}">
          <label>
            <span>${t("admin.users.form_email")}</span>
            <input name="email" type="email" value="${html(u.email)}" required />
          </label>

          <label>
            <span>${t("admin.users.form_name")}</span>
            <input name="display_name" value="${html(u.display_name || "")}" />
          </label>

          <label>
            <span>${t("admin.users.form_preferred_language")}</span>
            <select name="preferred_language">
              <option value="en" ${(!u.preferred_language || u.preferred_language === "en") ? "selected" : ""}>${t("settings.account.language_en")}</option>
              <option value="fr" ${u.preferred_language === "fr" ? "selected" : ""}>${t("settings.account.language_fr")}</option>
            </select>
          </label>

          <div class="admin-form-grid-2">
            <label>
              <span>${t("admin.users.form_valid_from")}</span>
              <input type="datetime-local" name="valid_from" value="${html(toInputDateTime(u.valid_from))}" />
            </label>

            <label>
              <span>${t("admin.users.form_expires")}</span>
              <input type="datetime-local" name="account_expires_at" value="${html(toInputDateTime(u.account_expires_at))}" />
            </label>
          </div>

          <div class="admin-checkbox-grid">
            <label class="checkbox-row">
              <input type="checkbox" name="is_super_admin" ${isSuperAdmin ? "checked" : ""} />
              <span>${t("admin.users.form_super_admin")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="is_active" ${isActive ? "checked" : ""} />
              <span>${t("admin.users.form_active")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="email_verified" ${isEmailVerified ? "checked" : ""} />
              <span>${t("admin.users.form_email_verified")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="can_use_local_space" ${Boolean(u.can_use_local_space) ? "checked" : ""} />
              <span>${t("admin.users.form_can_use_local_space")}</span>
            </label>
          </div>

          <button type="submit" class="btn btn-primary">${t("admin.users.form_update")}</button>
        </form>

        <form class="form-grid user-password-form admin-password-reset-box" data-user-id="${html(u.id)}">
          <h4>${t("admin.users.password_reset_title")}</h4>
          <p class="muted">${t("admin.users.password_reset_hint")}</p>

          <label>
            <span>${t("admin.users.password_reset_label")}</span>
            <input name="password" type="password" minlength="8" required />
          </label>

          <button type="submit" class="btn">${t("admin.users.password_reset_submit")}</button>
        </form>
      </div>
    </article>
  `;
}

function renderCreateUserBlock() {
  return `
    <details class="admin-section-card admin-create-user-block">
      <summary>
        <span>
          <strong>${t("admin.users.create_title")}</strong>
          <small>${t("admin.users.create_subtitle")}</small>
        </span>
      </summary>

      <form id="user-form" class="form-grid admin-create-user-form">
        <div class="admin-form-grid-2">
          <label>
            <span>${t("admin.users.form_email")}</span>
            <input name="email" type="email" placeholder="email@example.com" required />
          </label>

          <label>
            <span>${t("admin.users.form_name")}</span>
            <input name="display_name" placeholder="${t("admin.users.form_name")}" />
          </label>
        </div>

        <label>
          <span>${t("admin.users.form_creation_mode")}</span>
          <select name="creation_mode" id="user-creation-mode">
            <option value="password">${t("admin.users.mode_password")}</option>
            <option value="invitation">${t("admin.users.mode_invitation")}</option>
          </select>
        </label>

        <label>
          <span>${t("admin.users.form_preferred_language")}</span>
          <select name="preferred_language">
            <option value="en">${t("settings.account.language_en")}</option>
            <option value="fr">${t("settings.account.language_fr")}</option>
          </select>
        </label>

        <label id="user-password-row">
          <span>${t("admin.users.form_password")}</span>
          <input name="password" type="password" placeholder="${t("admin.users.form_password_placeholder")}" minlength="8" required />
        </label>

        <label id="user-force-password-change-row" class="checkbox-row">
          <input type="checkbox" name="force_password_change" checked />
          <span>${t("admin.users.form_force_password_change")}</span>
        </label>

        <div class="admin-form-grid-2">
          <label>
            <span>${t("admin.users.form_valid_from")}</span>
            <input type="datetime-local" name="valid_from" />
          </label>

          <label>
            <span>${t("admin.users.form_expires")}</span>
            <input type="datetime-local" name="account_expires_at" />
          </label>
        </div>

        <div class="admin-checkbox-grid">
          <label class="checkbox-row">
            <input type="checkbox" name="is_super_admin" />
            <span>${t("admin.users.form_super_admin")}</span>
          </label>

          <label class="checkbox-row">
            <input type="checkbox" name="email_verified" />
            <span>${t("admin.users.form_mark_email_verified")}</span>
          </label>

          <label class="checkbox-row">
            <input type="checkbox" name="can_use_local_space" />
            <span>${t("admin.users.form_can_use_local_space")}</span>
          </label>
        </div>

        <button type="submit" class="btn btn-primary">${t("admin.users.btn_create")}</button>
      </form>
    </details>
  `;
}

export function renderUserCardList(users, emailAvailable = true) {
  return users.map((u) => renderUserCard(u, emailAvailable)).join("");
}

function renderGeneralSettingsPanel(generalSettings = null) {
  const settings = generalSettings || {};

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="general" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.general.title")}</h3>
          <p class="muted">${t("admin.general.subtitle")}</p>
        </div>
        <span class="badge badge-ready">${t("admin.general.configured")}</span>
      </div>

      <div id="admin-general-feedback" hidden></div>

      <form id="admin-general-form" class="form-grid">
        <label>
          <span>${t("admin.general.app_name_label")}</span>
          <input name="app_name" type="text" value="${html(settings.app_name || "")}" />
        </label>

        <label>
          <span>${t("admin.general.app_tagline_label")}</span>
          <input name="app_tagline" type="text" value="${html(settings.app_tagline || "")}" />
        </label>

        <div class="detail-block">
          <h4>${t("admin.general.public_url_title")}</h4>
          <label>
            <span>${t("admin.general.public_url_label")}</span>
            <input
              name="public_base_url"
              type="url"
              value="${html(settings.public_base_url || "")}"
              placeholder="https://link2nas.example.com"
            />
          </label>
          <p class="muted">${t("admin.general.public_url_hint")}</p>
          ${settings.effective_public_base_url
            ? `<p class="muted">${t("admin.general.effective_public_url")} : <strong>${html(settings.effective_public_base_url)}</strong></p>`
            : ""}
        </div>

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">${t("admin.general.save")}</button>
        </div>
      </form>
    </section>
  `;
}

function renderSmtpSettingsPanel(smtpSettings = null) {
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

function renderSecuritySettingsPanel(securitySettings = null) {
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

export function renderAntiAbuseSection(data) {
  if (!data) {
    return `<p class="muted">${t("admin.security.anti_abuse.loading")}</p>`;
  }

  const backend = html(data.backend || "—");
  const redisConfigured = data.redis_url_configured
    ? t("admin.security.anti_abuse.yes")
    : t("admin.security.anti_abuse.no");
  const counters = Array.isArray(data.counters) ? data.counters : [];

  const rows = counters.map((c) => {
    const status = c.status === "ok"
      ? `<span class="badge badge-ready">${t("admin.security.anti_abuse.status_ok")}</span>`
      : `<span class="badge badge-warning">${t("admin.security.anti_abuse.status_unavailable")}</span>`;

    const hits = c.status === "ok" && c.estimated_hits != null
      ? html(String(c.estimated_hits))
      : "—";
    const identities = c.status === "ok" && c.active_identities != null
      ? html(String(c.active_identities))
      : "—";
    const ttl = c.ttl_seconds != null ? `${html(String(c.ttl_seconds))} s` : "—";

    return `
      <tr>
        <td>${html(c.label || c.kind)}</td>
        <td>${html(String(c.limit))}</td>
        <td>${html(String(c.window_seconds))} s</td>
        <td>${status}</td>
        <td>${hits}</td>
        <td>${identities}</td>
        <td>${ttl}</td>
        <td>
          <button type="button" class="btn btn-sm btn-secondary"
            data-action="reset-anti-abuse-kind" data-kind="${html(c.kind)}">
            ${t("admin.security.anti_abuse.reset_kind")}
          </button>
        </td>
      </tr>
    `;
  }).join("");

  const note = data.note
    ? `<p class="muted" style="margin-top:0.5rem">${html(data.note)}</p>`
    : "";

  return `
    <div class="anti-abuse-meta">
      <span class="muted">${t("admin.security.anti_abuse.backend")} :</span>
      <strong>${backend}</strong>
      &nbsp;·&nbsp;
      <span class="muted">${t("admin.security.anti_abuse.redis_configured")} :</span>
      <strong>${redisConfigured}</strong>
    </div>
    ${note}
    <div class="table-responsive" style="margin-top:0.75rem">
      <table class="admin-table">
        <thead>
          <tr>
            <th>${t("admin.security.anti_abuse.col_counter")}</th>
            <th>${t("admin.security.anti_abuse.col_limit")}</th>
            <th>${t("admin.security.anti_abuse.col_window")}</th>
            <th>${t("admin.security.anti_abuse.col_status")}</th>
            <th>${t("admin.security.anti_abuse.col_hits")}</th>
            <th>${t("admin.security.anti_abuse.col_identities")}</th>
            <th>${t("admin.security.anti_abuse.col_ttl")}</th>
            <th>${t("admin.security.anti_abuse.col_action")}</th>
          </tr>
        </thead>
        <tbody>
          ${rows || `<tr><td colspan="8" class="muted">${t("admin.security.anti_abuse.counters_unavailable")}</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function renderEmailTemplatesPanel() {
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

function renderCleanupSettingsPanel(cleanupSettings = null) {
  const retention = cleanupSettings?.retention || {};

  const torrentTmpDays = retention.torrent_tmp_days ?? 7;
  const completedJobsDays = retention.completed_jobs_days ?? 30;
  const failedJobsDays = retention.failed_jobs_days ?? 30;
  const cancelledJobsDays = retention.cancelled_jobs_days ?? 15;
  const expiredTokensDays = retention.expired_tokens_days ?? 7;

  // TODO V3/backlog: Advanced cleanup sections intentionally hidden for now.
  // Future sections: Manual cleanup details/results, User data cleanup.

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="cleanup" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.cleanup.title")}</h3>
          <p class="muted">${t("admin.cleanup.subtitle")}</p>
        </div>
        <span class="badge badge-ready">${t("admin.cleanup.configured")}</span>
      </div>

      <div id="admin-cleanup-feedback" hidden></div>

      <form id="admin-cleanup-form" class="form-grid">
        <div class="security-setting-grid">
          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.torrent_tmp_days")}</span>
            <div class="security-input-row">
              <input name="torrent_tmp_days" type="number" min="1" max="365" value="${html(torrentTmpDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.completed_jobs_days")}</span>
            <div class="security-input-row">
              <input name="completed_jobs_days" type="number" min="1" max="3650" value="${html(completedJobsDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.failed_jobs_days")}</span>
            <div class="security-input-row">
              <input name="failed_jobs_days" type="number" min="1" max="3650" value="${html(failedJobsDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.cancelled_jobs_days")}</span>
            <div class="security-input-row">
              <input name="cancelled_jobs_days" type="number" min="1" max="3650" value="${html(cancelledJobsDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.expired_tokens_days")}</span>
            <div class="security-input-row">
              <input name="expired_tokens_days" type="number" min="1" max="365" value="${html(expiredTokensDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>
        </div>

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">${t("admin.cleanup.save")}</button>
          <button type="button" class="btn btn-danger" data-action="run-admin-cleanup">
            ${t("admin.cleanup.run_now")}
          </button>
        </div>
      </form>
    </section>
  `;
}

function renderTimeoutsSettingsPanel(timeoutSettings = null) {
  const settings = timeoutSettings || {};

  const defaultSeconds = settings.default_seconds ?? 10;
  const realdebridSeconds = settings.realdebrid_seconds ?? 60;
  const alldebridSeconds = settings.alldebrid_seconds ?? 8;

  // TODO V3/backlog: Advanced timeout settings intentionally hidden for now.
  // Future sections: Provider HTTP timeouts, Destination timeouts, Worker/job timeouts.

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="timeouts" hidden>
      <div class="admin-section-title">
        <div>
          <h3>Timeouts</h3>
          <p class="muted">${t("admin.timeouts.subtitle")}</p>
        </div>
        <span class="badge badge-ready">${t("admin.timeouts.configured")}</span>
      </div>

      <div id="admin-timeouts-feedback" hidden></div>

      <form id="admin-timeouts-form" class="form-grid">
        <div class="timeout-setting-grid">
          <label class="timeout-setting-card">
            <span class="timeout-setting-label">${t("admin.timeouts.default_seconds")}</span>
            <div class="timeout-input-row">
              <input name="default_seconds" type="number" min="0" max="3600" value="${html(defaultSeconds)}" required />
              <span class="timeout-input-unit">${t("admin.timeouts.unit_seconds")}</span>
            </div>
          </label>

          <label class="timeout-setting-card">
            <span class="timeout-setting-label">${t("admin.timeouts.realdebrid_seconds")}</span>
            <div class="timeout-input-row">
              <input name="realdebrid_seconds" type="number" min="0" max="3600" value="${html(realdebridSeconds)}" required />
              <span class="timeout-input-unit">${t("admin.timeouts.unit_seconds")}</span>
            </div>
          </label>

          <label class="timeout-setting-card">
            <span class="timeout-setting-label">${t("admin.timeouts.alldebrid_seconds")}</span>
            <div class="timeout-input-row">
              <input name="alldebrid_seconds" type="number" min="0" max="3600" value="${html(alldebridSeconds)}" required />
              <span class="timeout-input-unit">${t("admin.timeouts.unit_seconds")}</span>
            </div>
          </label>
        </div>

        <div class="timeout-form-footer">
          <button type="submit" class="btn btn-primary">${t("admin.timeouts.save")}</button>
        </div>
      </form>
    </section>
  `;
}

function formatBytes(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = n;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size.toFixed(unitIndex === 0 ? 0 : 2)} ${units[unitIndex]}`;
}

function renderMaintenanceCheck(label, ok, message = "") {
  return `
    <article class="admin-placeholder-card">
      <div>
        <h4>${html(label)}</h4>
        <p class="muted">${html(message || (ok ? "OK" : t("admin.maintenance.error")))}</p>
      </div>
      <span class="badge ${ok ? "badge-ready" : "badge-failed"}">
        ${ok ? "OK" : "KO"}
      </span>
    </article>
  `;
}

function renderMaintenanceStatusPanel(maintenanceStatus = null) {
  const status = maintenanceStatus || {};
  const app = status.app || {};
  const database = status.database || {};
  const disk = status.disk || {};
  const paths = Array.isArray(status.paths) ? status.paths : [];

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="maintenance" hidden>
      <div class="admin-section-title">
        <div>
          <h3>Maintenance</h3>
          <p class="muted">${t("admin.maintenance.subtitle")}</p>
        </div>

        <button type="button" class="btn" data-action="refresh-admin-maintenance">
          ${t("admin.maintenance.refresh")}
        </button>
      </div>

      <div id="admin-maintenance-feedback" hidden></div>

      <div class="detail-block">
        <h4>${t("admin.maintenance.group_application")}</h4>
        <div class="admin-placeholder-grid">
          ${renderMaintenanceCheck(
            t("admin.maintenance.global_status"),
            Boolean(status.ok),
            status.generated_at
              ? `${t("admin.maintenance.generated_at")} ${formatDate(status.generated_at)}`
              : t("admin.maintenance.not_loaded")
          )}

          ${renderMaintenanceCheck(
            t("admin.maintenance.app_version"),
            true,
            `${app.name || "link2nas"} ${app.version || "unknown"} — debug: ${app.debug ? t("admin.maintenance.debug_yes") : t("admin.maintenance.debug_no")}`
          )}

          ${renderMaintenanceCheck(
            t("admin.maintenance.public_url"),
            Boolean(app.public_base_url),
            app.public_base_url || t("admin.maintenance.public_url_not_set")
          )}
        </div>
      </div>

      <div class="detail-block">
        <h4>${t("admin.maintenance.group_infrastructure")}</h4>
        <div class="admin-placeholder-grid">
          ${renderMaintenanceCheck(
            t("admin.maintenance.database"),
            Boolean(database.ok),
            `${database.backend || "unknown"} — ${database.message || ""}`
          )}

          ${renderMaintenanceCheck(
            t("admin.maintenance.disk_space"),
            Boolean(disk.ok),
            `${formatBytes(disk.free_bytes)} ${t("admin.maintenance.disk_free_label")} / ${formatBytes(disk.total_bytes)} — ${disk.percent_free ?? 0}% ${t("admin.maintenance.disk_free_pct")}`
          )}
        </div>
      </div>

      <div class="detail-block">
        <h4>${t("admin.maintenance.directories")}</h4>
        <div class="admin-placeholder-grid">
          ${
            paths.length
              ? paths.map((item) => renderMaintenanceCheck(
                  `${item.name}${item.required ? "" : ` ${t("admin.maintenance.optional")}`}`,
                  Boolean(item.ok),
                  `${item.path || "—"} — ${item.message || ""}`
                )).join("")
              : `<p class="muted">${t("admin.maintenance.no_directories")}</p>`
          }
        </div>
      </div>
    </section>
  `;
}

function renderJsonBlock(value) {
  return html(JSON.stringify(value || {}, null, 2));
}

function renderRuntimeSettingsPanel(runtimeSettings = null) {
  const dispatcher = runtimeSettings?.notifications?.dispatcher || {};
  const orchestrator = runtimeSettings?.jobs?.orchestrator || {};
  const localWorker = runtimeSettings?.downloads?.local_worker || {};

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="runtime" hidden>
      <div class="admin-section-title">
        <div>
          <h3>Runtime</h3>
          <p class="muted">${t("admin.runtime.subtitle")}</p>
        </div>

        <span class="badge ${dispatcher.enabled ? "badge-ready" : ""}">
          ${t(dispatcher.enabled ? "admin.runtime.badge_active" : "admin.runtime.badge_partial")}
        </span>
      </div>

      <div id="admin-runtime-feedback" hidden></div>

      <form id="admin-runtime-form" class="form-grid">

        <section class="detail-block">
          <h4>${t("admin.runtime.dispatcher_title")}</h4>

          <label class="checkbox-row">
            <input
              type="checkbox"
              name="notification_dispatcher_enabled"
              ${dispatcher.enabled ? "checked" : ""}
            />
            <span>${t("admin.runtime.dispatcher_enable")}</span>
          </label>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.dispatcher_interval")}</span>
              <div class="security-input-row">
                <input
                  name="notification_dispatcher_interval_seconds"
                  type="number"
                  min="1"
                  max="3600"
                  value="${html(dispatcher.interval_seconds ?? 60)}"
                  required
                />
                <span class="security-input-unit">${t("admin.runtime.unit_seconds")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.dispatcher_limit")}</span>
              <div class="security-input-row">
                <input
                  name="notification_dispatcher_limit"
                  type="number"
                  min="1"
                  max="200"
                  value="${html(dispatcher.limit ?? 25)}"
                  required
                />
              </div>
            </label>
          </div>

          <div class="kv-grid">
            <div class="kv-item">
              <strong>${t("admin.runtime.dispatcher_last_run")}</strong>
              <div>${dispatcher.last_run_at ? html(formatDate(dispatcher.last_run_at)) : "—"}</div>
            </div>

            <div class="kv-item">
              <strong>${t("admin.runtime.dispatcher_last_error")}</strong>
              <div>${dispatcher.last_error ? html(dispatcher.last_error) : "—"}</div>
            </div>
          </div>

          <details class="detail-block">
            <summary>${t("admin.runtime.dispatcher_last_result")}</summary>
            <pre>${renderJsonBlock(dispatcher.last_result)}</pre>
          </details>

          <div class="admin-form-actions">
            <button type="button" class="btn" data-action="run-notification-dispatcher-now">
              ${t("admin.runtime.dispatcher_run_now")}
            </button>

            <button type="button" class="btn" data-action="refresh-notification-dispatcher-status">
              ${t("admin.runtime.dispatcher_refresh")}
            </button>
          </div>
        </section>

        <section class="detail-block">
          <h4>${t("admin.runtime.orchestrator_title")}</h4>

          <label class="checkbox-row">
            <input
              type="checkbox"
              name="jobs_orchestrator_enabled"
              ${orchestrator.enabled ? "checked" : ""}
            />
            <span>${t("admin.runtime.orchestrator_enable")}</span>
          </label>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.orchestrator_interval")}</span>
              <div class="security-input-row">
                <input
                  name="jobs_orchestrator_interval_seconds"
                  type="number"
                  min="1"
                  max="3600"
                  value="${html(orchestrator.interval_seconds ?? 5)}"
                  required
                />
                <span class="security-input-unit">${t("admin.runtime.unit_seconds")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.orchestrator_max_jobs")}</span>
              <div class="security-input-row">
                <input
                  name="jobs_orchestrator_max_jobs_per_run"
                  type="number"
                  min="1"
                  max="500"
                  value="${html(orchestrator.max_jobs_per_run ?? 25)}"
                  required
                />
              </div>
            </label>
          </div>

          <div class="admin-checkbox-grid">
            <label class="checkbox-row">
              <input
                type="checkbox"
                name="jobs_orchestrator_auto_refresh_enabled"
                ${orchestrator.auto_refresh_enabled ? "checked" : ""}
              />
              <span>${t("admin.runtime.orchestrator_auto_refresh")}</span>
            </label>

            <label class="checkbox-row">
              <input
                type="checkbox"
                name="jobs_orchestrator_auto_unrestrict_enabled"
                ${orchestrator.auto_unrestrict_enabled ? "checked" : ""}
              />
              <span>${t("admin.runtime.orchestrator_auto_unrestrict")}</span>
            </label>

            <label class="checkbox-row">
              <input
                type="checkbox"
                name="jobs_orchestrator_auto_send_destination_enabled"
                ${orchestrator.auto_send_destination_enabled ? "checked" : ""}
              />
              <span>${t("admin.runtime.orchestrator_auto_send")}</span>
            </label>
          </div>
        </section>

        <section class="detail-block">
          <h4>${t("admin.runtime.worker_title")}</h4>

          <label class="checkbox-row">
            <input
              type="checkbox"
              name="local_worker_enabled"
              ${localWorker.enabled ? "checked" : ""}
            />
            <span>${t("admin.runtime.worker_enable")}</span>
          </label>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.worker_poll_interval")}</span>
              <div class="security-input-row">
                <input
                  name="local_worker_poll_interval_seconds"
                  type="number"
                  min="1"
                  max="3600"
                  value="${html(localWorker.poll_interval_seconds ?? 5)}"
                  required
                />
                <span class="security-input-unit">${t("admin.runtime.unit_seconds")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.worker_max_concurrent")}</span>
              <div class="security-input-row">
                <input
                  name="local_worker_max_concurrent_downloads"
                  type="number"
                  min="1"
                  max="20"
                  value="${html(localWorker.max_concurrent_downloads ?? 1)}"
                  required
                />
              </div>
            </label>
          </div>
        </section>

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">
            ${t("admin.runtime.save")}
          </button>
        </div>
      </form>
    </section>
  `;
}

function formatAnnouncementType(type) {
  const map = {
    news: "admin.announcements.type_news",
    maintenance: "admin.announcements.type_maintenance",
    incident: "admin.announcements.type_incident",
    security: "admin.announcements.type_security",
  };
  return t(map[type] || "admin.announcements.type_news");
}

function formatAnnouncementSeverity(severity) {
  const map = {
    info: "admin.announcements.severity_info",
    warning: "admin.announcements.severity_warning",
    critical: "admin.announcements.severity_critical",
  };
  return t(map[severity] || "admin.announcements.severity_info");
}

export function renderAnnouncementForm(ann = null, emailAvailable = false) {
  const isEdit = Boolean(ann?.id);
  const v = (field, fallback = "") => html(ann ? (ann[field] ?? fallback) : fallback);
  const checked = (field) => (ann ? Boolean(ann[field]) : false);

  return `
    <form id="${isEdit ? `announcement-edit-form-${ann.id}` : "announcement-create-form"}" class="form-grid announcement-form" ${isEdit ? `data-announcement-id="${html(ann.id)}"` : ""}>
      <label>
        <span>${t("admin.announcements.field_title")}</span>
        <input name="title" type="text" value="${v("title")}" required />
      </label>

      <label>
        <span>${t("admin.announcements.field_body")}</span>
        <textarea name="body" rows="4" required>${v("body")}</textarea>
      </label>

      <div class="admin-form-grid-2">
        <label>
          <span>${t("admin.announcements.field_type")}</span>
          <select name="type">
            <option value="news" ${(!ann || ann.type === "news") ? "selected" : ""}>${t("admin.announcements.type_news")}</option>
            <option value="maintenance" ${ann?.type === "maintenance" ? "selected" : ""}>${t("admin.announcements.type_maintenance")}</option>
            <option value="incident" ${ann?.type === "incident" ? "selected" : ""}>${t("admin.announcements.type_incident")}</option>
            <option value="security" ${ann?.type === "security" ? "selected" : ""}>${t("admin.announcements.type_security")}</option>
          </select>
        </label>

        <label>
          <span>${t("admin.announcements.field_severity")}</span>
          <select name="severity">
            <option value="info" ${(!ann || ann.severity === "info") ? "selected" : ""}>${t("admin.announcements.severity_info")}</option>
            <option value="warning" ${ann?.severity === "warning" ? "selected" : ""}>${t("admin.announcements.severity_warning")}</option>
            <option value="critical" ${ann?.severity === "critical" ? "selected" : ""}>${t("admin.announcements.severity_critical")}</option>
          </select>
        </label>
      </div>

      <div class="admin-form-grid-2">
        <label>
          <span>${t("admin.announcements.field_starts_at")}</span>
          <input name="starts_at" type="datetime-local" value="${html(toInputDateTime(ann?.starts_at))}" />
        </label>

        <label>
          <span>${t("admin.announcements.field_ends_at")}</span>
          <input name="ends_at" type="datetime-local" value="${html(toInputDateTime(ann?.ends_at))}" />
        </label>
      </div>

      <div class="admin-checkbox-grid">
        <label class="checkbox-row">
          <input type="checkbox" name="is_active" ${isEdit ? (checked("is_active") ? "checked" : "") : "checked"} />
          <span>${t("admin.announcements.field_is_active")}</span>
        </label>

        <label class="checkbox-row">
          <input type="checkbox" name="show_as_banner" ${checked("show_as_banner") ? "checked" : ""} />
          <span>${t("admin.announcements.field_show_as_banner")}</span>
        </label>

        <label class="checkbox-row">
          <input type="checkbox" name="require_acknowledgement" ${checked("require_acknowledgement") ? "checked" : ""} />
          <span>${t("admin.announcements.field_require_acknowledgement")}</span>
        </label>
        <p class="announcement-form-hint">${t("admin.announcements.field_require_acknowledgement_hint")}</p>

        <label class="checkbox-row">
          <input type="checkbox" name="track_open" ${checked("track_open") ? "checked" : ""} />
          <span>${t("admin.announcements.field_track_open")}</span>
        </label>

        <label class="checkbox-row ${emailAvailable ? "" : "is-disabled"}">
          <input type="checkbox" name="send_email" ${emailAvailable ? (isEdit && ann?.send_email ? "checked" : "") : "disabled"} />
          <span>${t("admin.announcements.field_send_email")}</span>
        </label>
      </div>

      <p class="announcement-form-hint">${emailAvailable
        ? t("admin.announcements.email_eligible_hint")
        : t("admin.announcements.email_smtp_required")
      }</p>

      <div class="admin-form-actions">
        <button type="submit" class="btn btn-primary">
          ${isEdit ? t("admin.announcements.update_submit") : t("admin.announcements.create_submit")}
        </button>
        ${isEdit ? `<button type="button" class="btn" data-action="cancel-announcement-edit" data-id="${html(ann.id)}">${t("admin.announcements.cancel_edit")}</button>` : ""}
      </div>
    </form>
  `;
}

function renderAnnouncementCard(ann) {
  const stats = ann.stats || {};
  const isActive = Boolean(ann.is_active);

  return `
    <article class="announcement-card" data-announcement-id="${html(ann.id)}">
      <div class="announcement-card-header">
        <div class="announcement-badges">
          <span class="announcement-severity-badge severity-${html(ann.severity || "info")}">${html(formatAnnouncementSeverity(ann.severity))}</span>
          <span class="announcement-type-badge">${html(formatAnnouncementType(ann.type))}</span>
          <span class="badge ${isActive ? "badge-ready" : ""}">${t(isActive ? "admin.announcements.badge_active" : "admin.announcements.badge_inactive")}</span>
          ${ann.show_as_banner ? `<span class="badge">${t("admin.announcements.field_show_as_banner")}</span>` : ""}
          ${ann.require_acknowledgement ? `<span class="badge">${t("admin.announcements.field_require_acknowledgement")}</span>` : ""}
        </div>
      </div>

      <div class="announcement-card-title">${html(ann.title)}</div>
      <div class="announcement-card-body-preview">${html(ann.body)}</div>

      <div class="announcement-card-meta">
        ${ann.starts_at ? `<span>${t("admin.announcements.field_starts_at")}: <strong>${html(formatDate(ann.starts_at))}</strong></span>` : ""}
        ${ann.ends_at ? `<span>${t("admin.announcements.field_ends_at")}: <strong>${html(formatDate(ann.ends_at))}</strong></span>` : ""}
        <span>${t("admin.announcements.created_at")}: <strong>${ann.created_at ? html(formatDate(ann.created_at)) : "—"}</strong></span>
      </div>

      ${Object.keys(stats).length ? `
        <div class="announcement-card-stats">
          <span class="announcement-stat"><strong>${stats.opened ?? 0}</strong> ${t("admin.announcements.tracking_opened")}</span>
          <span class="announcement-stat"><strong>${stats.read ?? 0}</strong> ${t("admin.announcements.tracking_read")}</span>
          <span class="announcement-stat"><strong>${stats.acknowledged ?? 0}</strong> ${t("admin.announcements.tracking_acked")}</span>
          ${stats.targeted_email_recipients != null ? `<span class="announcement-stat"><strong>${stats.targeted_email_recipients}</strong> ${t("admin.announcements.tracking_targeted")}</span>` : ""}
        </div>
      ` : ""}

      <div class="announcement-card-actions">
        <button type="button" class="btn" data-action="edit-announcement" data-id="${html(ann.id)}">
          ${t("admin.announcements.edit")}
        </button>
        <button type="button" class="btn" data-action="${isActive ? "deactivate-announcement" : "activate-announcement"}" data-id="${html(ann.id)}">
          ${isActive ? t("admin.announcements.toggle_deactivate") : t("admin.announcements.toggle_activate")}
        </button>
        <button type="button" class="btn" data-action="view-announcement-tracking" data-id="${html(ann.id)}">
          ${t("admin.announcements.tracking")}
        </button>
        <button type="button" class="btn btn-danger" data-action="delete-announcement" data-id="${html(ann.id)}">
          ${t("admin.announcements.delete")}
        </button>
      </div>

      <div class="announcement-edit-inline" data-for-announcement="${html(ann.id)}" hidden></div>
      <div class="announcement-tracking-inline" data-for-tracking="${html(ann.id)}" hidden></div>
    </article>
  `;
}

export function renderAnnouncementTrackingPanel(tracking) {
  if (!tracking) return "";

  const ann = tracking.announcement || {};
  const stats = tracking.stats || {};
  const reads = Array.isArray(tracking.reads) ? tracking.reads : [];

  const showEmailTracking =
    Boolean(ann.send_email) ||
    (stats.targeted_email_recipients ?? 0) > 0 ||
    (stats.email_sent ?? 0) > 0 ||
    (stats.email_failed ?? 0) > 0 ||
    reads.some((r) => r.email_sent_at || r.email_status || r.email_error);

  return `
    <div class="announcement-tracking-panel">
      <div class="admin-section-title" style="margin-bottom:12px">
        <div>
          <h4>${t("admin.announcements.tracking_title")}: ${html(ann.title || "")}</h4>
        </div>
      </div>

      <div class="announcement-tracking-stats">
        <div class="announcement-tracking-stat-card">
          <span class="announcement-tracking-stat-value">${stats.opened ?? 0}</span>
          <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_opened")}</span>
        </div>
        <div class="announcement-tracking-stat-card">
          <span class="announcement-tracking-stat-value">${stats.read ?? 0}</span>
          <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_read")}</span>
        </div>
        <div class="announcement-tracking-stat-card">
          <span class="announcement-tracking-stat-value">${stats.acknowledged ?? 0}</span>
          <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_acked")}</span>
        </div>
        ${showEmailTracking ? `
          <div class="announcement-tracking-stat-card">
            <span class="announcement-tracking-stat-value">${stats.email_sent ?? 0}</span>
            <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_email_sent")}</span>
          </div>
          <div class="announcement-tracking-stat-card">
            <span class="announcement-tracking-stat-value">${stats.email_failed ?? 0}</span>
            <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_email_failed")}</span>
          </div>
          <div class="announcement-tracking-stat-card">
            <span class="announcement-tracking-stat-value">${stats.targeted_email_recipients ?? 0}</span>
            <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_targeted")}</span>
          </div>
        ` : ""}
      </div>

      ${reads.length === 0 ? `<p class="muted">${t("admin.announcements.no_tracking")}</p>` : `
        <table class="announcement-tracking-table">
          <thead>
            <tr>
              <th>${t("admin.announcements.tracking_col_email")}</th>
              <th>${t("admin.announcements.tracking_col_name")}</th>
              <th>${t("admin.announcements.tracking_col_opened")}</th>
              <th>${t("admin.announcements.tracking_col_read")}</th>
              <th>${t("admin.announcements.tracking_col_acked")}</th>
              ${showEmailTracking ? `
                <th>${t("admin.announcements.tracking_col_email_sent")}</th>
                <th>${t("admin.announcements.tracking_col_email_status")}</th>
              ` : ""}
            </tr>
          </thead>
          <tbody>
            ${reads.map((r) => `
              <tr>
                <td>${html(r.email || "—")}</td>
                <td>${html(r.display_name || "—")}</td>
                <td>${r.opened_at ? html(formatDate(r.opened_at)) : "—"}</td>
                <td>${r.read_at ? html(formatDate(r.read_at)) : "—"}</td>
                <td>${r.acknowledged_at ? html(formatDate(r.acknowledged_at)) : "—"}</td>
                ${showEmailTracking ? `
                  <td>${r.email_sent_at ? html(formatDate(r.email_sent_at)) : "—"}</td>
                  <td>${html(r.email_status || "—")}</td>
                ` : ""}
              </tr>
            `).join("")}
          </tbody>
        </table>
      `}
    </div>
  `;
}

export function renderAnnouncementsAdminPanel(announcements = [], emailAvailable = false) {
  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="announcements" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.announcements.title")}</h3>
          <p class="muted">${t("admin.announcements.subtitle")}</p>
        </div>
        <span class="badge">${announcements.length} ${announcements.length > 1 ? t("admin.announcements.count_plural") : t("admin.announcements.count_singular")}</span>
      </div>

      <div id="admin-announcements-feedback" hidden></div>

      <details class="admin-section-card admin-create-user-block">
        <summary>
          <span>
            <strong>${t("admin.announcements.create_title")}</strong>
          </span>
        </summary>
        ${renderAnnouncementForm(null, emailAvailable)}
      </details>

      <div class="announcement-admin-list">
        ${announcements.length
          ? announcements.map(renderAnnouncementCard).join("")
          : `<p class="muted">${t("admin.announcements.no_items")}</p>`
        }
      </div>
    </section>
  `;
}

function renderAdminSectionPlaceholders(
  smtpSettings = null,
  securitySettings = null,
  cleanupSettings = null,
  maintenanceStatus = null,
  timeoutSettings = null,
  runtimeSettings = null,
  generalSettings = null,
  announcements = [],
  emailAvailable = false
) {
  return `
    ${renderGeneralSettingsPanel(generalSettings)}
    ${renderAnnouncementsAdminPanel(announcements, emailAvailable)}
    ${renderSmtpSettingsPanel(smtpSettings)}
    ${renderEmailTemplatesPanel()}
    ${renderSecuritySettingsPanel(securitySettings)}
    ${renderCleanupSettingsPanel(cleanupSettings)}

    ${renderTimeoutsSettingsPanel(timeoutSettings)}
    ${renderRuntimeSettingsPanel(runtimeSettings)}

    ${renderMaintenanceStatusPanel(maintenanceStatus)}
  `;
}


export function renderUsersPanel(
  users = [],
  smtpSettings = null,
  securitySettings = null,
  cleanupSettings = null,
  maintenanceStatus = null,
  timeoutSettings = null,
  runtimeSettings = null,
  options = {},
  generalSettings = null,
  announcements = []
) {
  const container = document.getElementById("users-panel");
  if (!container) return;

  const singleUserMode = Boolean(options.singleUserMode);
  const emailAvailable = Boolean(options.emailAvailable !== false);

  const usersTab = singleUserMode
    ? ""
    : `<button type="button" class="admin-tab is-active" data-admin-tab="users">${t("admin.tab.users")}</button>`;

  const usersPanel = singleUserMode
    ? ""
    : `
      <section class="admin-section-card admin-tab-panel" data-admin-panel="users">
        <div class="admin-section-title">
          <div>
            <h3>${t("admin.users.title")}</h3>
            <p class="muted">${t("admin.users.subtitle")}</p>
          </div>
          <span class="badge">${users.length} ${users.length > 1 ? t("admin.users.count_plural") : t("admin.users.count_singular")}</span>
        </div>

        <div id="admin-users-feedback" hidden></div>

        <div class="admin-users-toolbar">
          <input
            id="admin-users-search"
            type="search"
            placeholder="${t("admin.users.search_placeholder")}"
          />
          <div class="admin-users-filters">
            <button type="button" class="filter-chip is-active" data-admin-users-filter="all">${t("admin.users.filter_all")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="active">${t("admin.users.filter_active")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="disabled">${t("admin.users.filter_disabled")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="super-admin">${t("admin.users.filter_super_admin")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="email-unverified">${t("admin.users.filter_email_unverified")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="expired">${t("admin.users.filter_expired")}</button>
          </div>
        </div>

        ${renderCreateUserBlock()}

        <div class="admin-users-list">
          ${users.length ? users.map((u) => renderUserCard(u, emailAvailable)).join("") : `<div class="empty-state">${t("admin.users.empty")}</div>`}
        </div>
      </section>
    `;

  container.innerHTML = `
    <div class="admin-page">
      <div class="section-header admin-page-header">
        <div>
          <h2>${t("admin.page.title")}</h2>
          <p class="muted">
            ${singleUserMode ? t("admin.page.subtitle_single_user") : t("admin.page.subtitle")}
          </p>
        </div>

        ${
          singleUserMode
            ? `<span class="badge badge-warning">Single-user mode</span>`
            : ""
        }
      </div>

      <div class="admin-tabs">
        ${usersTab}
        <button type="button" class="admin-tab" data-admin-tab="general">${t("admin.tab.general")}</button>
        <button type="button" class="admin-tab" data-admin-tab="announcements">${t("admin.tab.announcements")}</button>
        <button type="button" class="admin-tab ${singleUserMode ? "is-active" : ""}" data-admin-tab="maintenance">${t("admin.tab.maintenance")}</button>
        <button type="button" class="admin-tab" data-admin-tab="smtp">${t("admin.tab.smtp")}</button>
        <button type="button" class="admin-tab" data-admin-tab="email-templates">${t("admin.tab.email_templates")}</button>
        <button type="button" class="admin-tab" data-admin-tab="security">${t("admin.tab.security")}</button>
        <button type="button" class="admin-tab" data-admin-tab="timeouts">${t("admin.tab.timeouts")}</button>
        <button type="button" class="admin-tab" data-admin-tab="runtime">${t("admin.tab.runtime")}</button>
        <button type="button" class="admin-tab" data-admin-tab="cleanup">${t("admin.tab.cleanup")}</button>
      </div>

      ${
        singleUserMode
          ? `
            <section class="admin-section-card">
              <div class="admin-section-title">
                <div>
                  <h3>${t("admin.users.single_user_warning_title")}</h3>
                  <p class="muted">${t("admin.users.single_user_warning_text")}</p>
                </div>
              </div>
            </section>
          `
          : ""
      }

      ${usersPanel}
      ${renderAdminSectionPlaceholders(
        smtpSettings,
        securitySettings,
        cleanupSettings,
        maintenanceStatus,
        timeoutSettings,
        runtimeSettings,
        generalSettings,
        announcements,
        emailAvailable
      )}
    </div>
  `;
}