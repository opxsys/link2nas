import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";

export function validatePasswordConfirmation(form) {
  const password = String(form.password?.value || "");
  const passwordConfirm = String(form.password_confirm?.value || "");

  if (password.length < 8) {
    showAppMessage(t("auth.error.password_too_short"), "error");
    return null;
  }

  if (password !== passwordConfirm) {
    showAppMessage(t("auth.error.passwords_mismatch"), "error");
    return null;
  }

  return password;
}

export function validateForcedPasswordChangeForm(form) {
  const currentPassword = String(form.current_password?.value || "");
  const newPassword = String(form.new_password?.value || "");
  const newPasswordConfirm = String(form.new_password_confirm?.value || "");

  if (!currentPassword) {
    showAppMessage(t("auth.error.temp_password_required"), "error");
    return null;
  }

  if (newPassword.length < 8) {
    showAppMessage(t("auth.error.new_password_too_short"), "error");
    return null;
  }

  if (newPassword !== newPasswordConfirm) {
    showAppMessage(t("auth.error.new_passwords_mismatch"), "error");
    return null;
  }

  if (currentPassword === newPassword) {
    showAppMessage(t("auth.error.new_password_same_as_temp"), "error");
    return null;
  }

  return {
    current_password: currentPassword,
    new_password: newPassword,
  };
}
