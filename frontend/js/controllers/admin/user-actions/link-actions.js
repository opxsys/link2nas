import { createUserInvitation, createUserPasswordResetLink } from "../../../api.js";
import { t } from "../../../i18n/index.js";
import { showLinkModal } from "../../../ui/modals.js";
import { showUserActionError } from "./helpers.js";

export async function handleUserLinkAction(action, id) {
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
      showUserActionError(error);
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
      showUserActionError(error);
    }
    return true;
  }

  return false;
}
