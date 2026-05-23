import { resetAdminAntiAbuseAll, resetAdminAntiAbuseKind } from "../../api.js";
import { t } from "../../i18n/index.js";
import { showConfirmModal } from "../../ui/modals.js";
import { showAdminFeedback } from "./feedback.js";
import { loadAntiAbuseSection } from "./anti-abuse.js";

export async function handleAntiAbuseAction(action, button) {
  if (action === "refresh-anti-abuse") {
    try {
      await loadAntiAbuseSection();
      showAdminFeedback("anti-abuse", t("messages.admin_maintenance_refreshed"), "success");
    } catch (error) {
      showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "reset-anti-abuse-all") {
    const confirmed = await showConfirmModal({
      title: t("admin.security.anti_abuse.reset_all_confirm_title"),
      message: t("admin.security.anti_abuse.reset_all_confirm_message"),
      confirmLabel: t("admin.security.anti_abuse.reset_all"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return true;

    try {
      await resetAdminAntiAbuseAll();
      await loadAntiAbuseSection();
      showAdminFeedback("anti-abuse", t("messages.admin_anti_abuse_reset_all"), "success");
    } catch (error) {
      showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "reset-anti-abuse-kind") {
    const kind = button.dataset.kind;
    if (!kind) return true;

    const confirmed = await showConfirmModal({
      title: t("admin.security.anti_abuse.reset_kind_confirm_title"),
      message: t("admin.security.anti_abuse.reset_kind_confirm_message"),
      confirmLabel: t("admin.security.anti_abuse.reset_kind"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return true;

    try {
      await resetAdminAntiAbuseKind(kind);
      await loadAntiAbuseSection();
      showAdminFeedback("anti-abuse", t("messages.admin_anti_abuse_reset_kind"), "success");
    } catch (error) {
      showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  return false;
}
