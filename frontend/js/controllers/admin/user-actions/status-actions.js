import { disableUser, enableUser, verifyUserEmail, deleteUser } from "../../../api.js";
import { t } from "../../../i18n/index.js";
import { showConfirmModal } from "../../../ui/modals.js";
import { showAdminFeedback } from "../feedback.js";
import { reloadUsersAdminTab, showUserActionError } from "./helpers.js";

export async function handleUserStatusAction(action, id) {
  if (action === "disable-user") {
    try {
      await disableUser(id);
      await reloadUsersAdminTab();
      showAdminFeedback("users", t("messages.admin_user_disabled"), "success");
    } catch (error) {
      showUserActionError(error);
    }
    return true;
  }

  if (action === "enable-user") {
    try {
      await enableUser(id);
      await reloadUsersAdminTab();
      showAdminFeedback("users", t("messages.admin_user_enabled"), "success");
    } catch (error) {
      showUserActionError(error);
    }
    return true;
  }

  if (action === "verify-user-email") {
    try {
      await verifyUserEmail(id);
      await reloadUsersAdminTab();
      showAdminFeedback("users", t("messages.admin_user_email_verified"), "success");
    } catch (error) {
      showUserActionError(error);
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
      await reloadUsersAdminTab();
      showAdminFeedback("users", t("messages.admin_user_deleted"), "success");
    } catch (error) {
      showUserActionError(error);
    }
    return true;
  }

  return false;
}
