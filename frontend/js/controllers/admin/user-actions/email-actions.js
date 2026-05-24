import { sendUserInvitationEmail, sendUserPasswordResetEmail } from "../../../api.js";
import { t } from "../../../i18n/index.js";
import { showConfirmModal } from "../../../ui/modals.js";
import { showAdminFeedback } from "../feedback.js";
import { isSmtpConfigured, showUserActionError } from "./helpers.js";

export async function handleUserEmailAction(action, id) {
  if (action === "send-user-invitation-email") {
    if (!isSmtpConfigured()) {
      showAdminFeedback("users", t("email.smtp_configure_hint"), "error");
      return true;
    }

    const confirmed = await showConfirmModal({
      title: t("admin.users.confirm_send_invite_title"),
      message: t("admin.users.confirm_send_invite_message"),
      confirmLabel: t("admin.users.confirm_send"),
      cancelLabel: t("common.cancel"),
    });

    if (!confirmed) return true;

    try {
      await sendUserInvitationEmail(id);
      showAdminFeedback("users", t("messages.admin_user_invitation_sent"), "success");
    } catch (error) {
      showUserActionError(error);
    }
    return true;
  }

  if (action === "send-user-password-reset-email") {
    if (!isSmtpConfigured()) {
      showAdminFeedback("users", t("email.smtp_configure_hint"), "error");
      return true;
    }

    const confirmed = await showConfirmModal({
      title: t("admin.users.confirm_send_reset_title"),
      message: t("admin.users.confirm_send_reset_message"),
      confirmLabel: t("admin.users.confirm_send"),
      cancelLabel: t("common.cancel"),
    });

    if (!confirmed) return true;

    try {
      await sendUserPasswordResetEmail(id);
      showAdminFeedback("users", t("messages.admin_user_reset_sent"), "success");
    } catch (error) {
      showUserActionError(error);
    }
    return true;
  }

  return false;
}
