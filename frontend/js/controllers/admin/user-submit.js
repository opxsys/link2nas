import { createUser, updateUser, resetUserPassword } from "../../api.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { showLinkModal } from "../../ui/modals.js";
import { showAdminFeedback } from "./feedback.js";
import { getOptionalDatetimeValue } from "./payloads.js";
import { loadAdmin, switchAdminTab } from "./index.js";

export async function handleUserSubmit(form) {
  if (form.id === "user-form") {
    const creationMode = form.creation_mode?.value || "password";

    try {
      const result = await createUser({
        email: form.email.value,
        display_name: form.display_name.value,
        creation_mode: creationMode,
        password: creationMode === "password" ? form.password.value : undefined,
        force_password_change: creationMode === "password"
          ? Boolean(form.force_password_change?.checked)
          : false,
        is_super_admin: Boolean(form.is_super_admin.checked),
        email_verified: Boolean(form.email_verified?.checked),
        valid_from: getOptionalDatetimeValue(form, "valid_from"),
        account_expires_at: getOptionalDatetimeValue(form, "account_expires_at"),
        preferred_language: form.preferred_language.value,
        can_use_local_space: Boolean(form.can_use_local_space?.checked),
      });

      form.reset();
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_created"), "success");

      if (result.invitation?.invitation_url) {
        await showLinkModal({
          title: t("admin.users.modal_invite_title"),
          message: t("admin.users.modal_invite_message_create"),
          link: result.invitation.invitation_url,
          expiresAt: result.invitation.expires_at,
          copyLabel: t("common.copy"),
          closeLabel: t("common.close"),
        });
      }
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }

    return true;
  }

  if (form.classList.contains("user-edit-form")) {
    const userId = form.dataset.userId;

    try {
      await updateUser(userId, {
        email: form.email.value,
        display_name: form.display_name.value,
        is_super_admin: Boolean(form.is_super_admin.checked),
        is_active: Boolean(form.is_active.checked),
        email_verified: Boolean(form.email_verified.checked),
        valid_from: getOptionalDatetimeValue(form, "valid_from"),
        account_expires_at: getOptionalDatetimeValue(form, "account_expires_at"),
        preferred_language: form.preferred_language.value,
        can_use_local_space: Boolean(form.can_use_local_space?.checked),
      });

      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_updated"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }

    return true;
  }

  if (form.classList.contains("user-password-form")) {
    const userId = form.dataset.userId;

    try {
      await resetUserPassword(userId, form.password.value);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_password_reset"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }

    return true;
  }

  return false;
}
