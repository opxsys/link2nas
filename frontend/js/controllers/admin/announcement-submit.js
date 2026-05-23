import { createAdminAnnouncement, updateAdminAnnouncement } from "../../api.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { showAdminFeedback } from "./feedback.js";
import { buildAnnouncementPayload } from "./payloads.js";
import { loadAdmin, switchAdminTab } from "./index.js";

export async function handleAnnouncementSubmit(form) {
  if (form.id === "announcement-create-form") {
    const payload = buildAnnouncementPayload(form);
    try {
      await createAdminAnnouncement(payload);
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      const details = document.querySelector('[data-admin-panel="announcements"] details');
      if (details) details.open = false;
      showAdminFeedback("announcements", t("admin.announcements.created"), "success");
    } catch (error) {
      const msg = error.status === 503
        ? t("admin.announcements.email_send_failed_smtp")
        : error.message || t("messages.admin_action_error");
      showAdminFeedback("announcements", msg, "error");
    }
    return true;
  }

  if (form.classList.contains("announcement-edit-form-inline")) {
    const annId = form.dataset.announcementId;
    if (!annId) return true;
    const payload = buildAnnouncementPayload(form);
    try {
      await updateAdminAnnouncement(annId, payload);
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      showAdminFeedback("announcements", t("admin.announcements.updated"), "success");
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  return false;
}
