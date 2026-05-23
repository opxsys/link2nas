import {
  disableUser,
  enableUser,
  verifyUserEmail,
  createUserInvitation,
  createUserPasswordResetLink,
  sendUserInvitationEmail,
  sendUserPasswordResetEmail,
  deleteUser,
} from "../../api.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { showConfirmModal, showLinkModal } from "../../ui/modals.js";
import { showAdminFeedback } from "./feedback.js";
import { loadAdmin, switchAdminTab } from "./index.js";

export async function handleUserAction(action, button) {
  const id = button.dataset.id;

  if (action === "toggle-user-edit") {
    const card = button.closest("[data-user-id]");
    const editContent = card?.querySelector(".admin-user-edit-content");
    if (editContent) {
      editContent.hidden = !editContent.hidden;
      button.classList.toggle("is-active", !editContent.hidden);
    }
    return true;
  }

  if (action === "disable-user") {
    try {
      await disableUser(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_disabled"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "enable-user") {
    try {
      await enableUser(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_enabled"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "verify-user-email") {
    try {
      await verifyUserEmail(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_email_verified"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "create-user-invitation") {
    try {
      const result = await createUserInvitation(id);
      await showLinkModal({
        title: t("admin.users.modal_invite_title"),
        message: t("admin.users.modal_invite_message_resend"),
        link: result.invitation_url,
        expiresAt: result.expires_at,
        copyLabel: t("common.copy"),
        closeLabel: t("common.close"),
      });
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "send-user-invitation-email") {
    const smtpOk = !!(state.smtpSettings?.enabled && state.smtpSettings?.host && state.smtpSettings?.port && state.smtpSettings?.from_email);
    if (!smtpOk) {
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
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "create-user-password-reset-link") {
    try {
      const result = await createUserPasswordResetLink(id);
      await showLinkModal({
        title: t("admin.users.modal_reset_title"),
        message: t("admin.users.modal_reset_message"),
        link: result.reset_url,
        expiresAt: result.expires_at,
        copyLabel: t("common.copy"),
        closeLabel: t("common.close"),
      });
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "send-user-password-reset-email") {
    const smtpOk = !!(state.smtpSettings?.enabled && state.smtpSettings?.host && state.smtpSettings?.port && state.smtpSettings?.from_email);
    if (!smtpOk) {
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
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "delete-user") {
    const confirmed = await showConfirmModal({
      title: t("admin.users.confirm_delete_title"),
      message: t("admin.users.confirm_delete_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return true;

    try {
      await deleteUser(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_deleted"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  return false;
}
