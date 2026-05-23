import {
  updateAdminAnnouncement,
  deleteAdminAnnouncement,
  getAdminAnnouncementTracking,
} from "../../api.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { renderAnnouncementForm, renderAnnouncementTrackingPanel } from "../../render/admin.js";
import { showConfirmModal } from "../../ui/modals.js";
import { showAdminFeedback } from "./feedback.js";
import { loadAdmin, switchAdminTab } from "./index.js";

export async function handleAnnouncementAction(action, button) {
  const id = button.dataset.id;

  if (action === "edit-announcement") {
    const annId = id;
    if (!annId) return true;
    const ann = state.adminAnnouncements.find((a) => a.id === annId);
    if (!ann) return true;
    const inlineEl = document.querySelector(`.announcement-edit-inline[data-for-announcement="${annId}"]`);
    if (!inlineEl) return true;
    if (!inlineEl.hidden) {
      inlineEl.hidden = true;
      return true;
    }
    const emailAvailableForForm = Boolean(state.currentUser?.email_sending_available);
    inlineEl.innerHTML = renderAnnouncementForm(ann, emailAvailableForForm);
    const inlineForm = inlineEl.querySelector("form");
    if (inlineForm) inlineForm.classList.add("announcement-edit-form-inline");
    inlineEl.hidden = false;
    return true;
  }

  if (action === "cancel-announcement-edit") {
    const annId = id;
    const inlineEl = document.querySelector(`.announcement-edit-inline[data-for-announcement="${annId}"]`);
    if (inlineEl) inlineEl.hidden = true;
    return true;
  }

  if (action === "delete-announcement") {
    const annId = id;
    if (!annId) return true;
    const confirmed = await showConfirmModal({
      title: t("admin.announcements.confirm_delete_title"),
      message: t("admin.announcements.confirm_delete"),
      confirmLabel: t("admin.announcements.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return true;
    try {
      await deleteAdminAnnouncement(annId);
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      showAdminFeedback("announcements", t("admin.announcements.deleted"), "success");
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "activate-announcement" || action === "deactivate-announcement") {
    const annId = id;
    if (!annId) return true;
    const isActivating = action === "activate-announcement";
    try {
      await updateAdminAnnouncement(annId, { is_active: isActivating });
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      showAdminFeedback("announcements", t("admin.announcements.updated"), "success");
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "view-announcement-tracking") {
    const annId = id;
    if (!annId) return true;
    const inlineEl = document.querySelector(`.announcement-tracking-inline[data-for-tracking="${annId}"]`);
    if (!inlineEl) return true;
    if (!inlineEl.hidden) {
      inlineEl.hidden = true;
      return true;
    }
    try {
      const tracking = await getAdminAnnouncementTracking(annId);
      state.announcementTrackingById[annId] = tracking;
      inlineEl.innerHTML = renderAnnouncementTrackingPanel(tracking);
      inlineEl.hidden = false;
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  return false;
}
