import { t } from "../../../i18n/index.js";
import { html, toInputDateTime } from "../utils.js";

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
