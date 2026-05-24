import { t } from "../../../../i18n/index.js";

export function getUserCardFlags(u) {
  return {
    isActive: Boolean(u.is_active),
    isSuperAdmin: Boolean(u.is_super_admin),
    isEmailVerified: Boolean(u.email_verified),
    canUseLocalSpace: Boolean(u.can_use_local_space),
  };
}

export function getSmtpDisabledAttrs(emailAvailable) {
  if (emailAvailable) return "";
  return `disabled title="${t("email.smtp_configure_hint")}"`;
}
