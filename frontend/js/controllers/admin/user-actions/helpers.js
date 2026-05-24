import { state } from "../../../state.js";
import { t } from "../../../i18n/index.js";
import { showAdminFeedback } from "../feedback.js";
import { loadAdmin, switchAdminTab } from "../index.js";

export async function reloadUsersAdminTab() {
  state.activeAdminTab = "users";
  await loadAdmin();
  switchAdminTab("users");
}

export function showUserActionError(error) {
  showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
}

export function isSmtpConfigured() {
  return !!(
    state.smtpSettings?.enabled &&
    state.smtpSettings?.host &&
    state.smtpSettings?.port &&
    state.smtpSettings?.from_email
  );
}
