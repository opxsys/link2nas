import { t } from "../../i18n/index.js";

export const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };

export function formatSeverityLabel(severity) {
  if (severity === "critical") return t("admin.announcements.severity_critical");
  if (severity === "warning") return t("admin.announcements.severity_warning");
  return t("admin.announcements.severity_info");
}

function announcementNeedsAttention(ann) {
  if (Boolean(ann.require_acknowledgement)) return !ann.user_status?.acknowledged_at;
  return !ann.user_status?.read_at;
}

export function getAnnouncementsUnreadCount(announcements) {
  return (announcements || []).filter(announcementNeedsAttention).length;
}
