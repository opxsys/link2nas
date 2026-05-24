import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { escapeForModalHtml } from "../../ui/modals.js";
import { SEVERITY_ORDER, formatSeverityLabel } from "./helpers.js";

export function pickBannerAnnouncement(announcements) {
  const dismissed = state.dismissedAnnouncementBannerIds;
  const bannerCandidates = (announcements || []).filter((a) => {
    if (!a.show_as_banner) return false;
    if (dismissed.includes(a.id)) return false;
    const status = a.user_status || {};
    if (Boolean(a.require_acknowledgement) && status.acknowledged_at) return false;
    if (!a.require_acknowledgement && status.read_at) return false;
    return true;
  });
  if (!bannerCandidates.length) return null;
  return bannerCandidates.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 3;
    const sb = SEVERITY_ORDER[b.severity] ?? 3;
    if (sa !== sb) return sa - sb;
    return (b.created_at || "").localeCompare(a.created_at || "");
  })[0];
}

export function renderAnnouncementBanner(ann) {
  const banner = document.getElementById("announcement-banner");
  if (!banner) return;

  if (!ann) {
    banner.hidden = true;
    banner.className = "";
    banner.innerHTML = "";
    return;
  }

  const severityClass = `announcement-severity-${ann.severity || "info"}`;
  banner.className = severityClass;
  banner.hidden = false;

  const bodyPreview = String(ann.body || "").slice(0, 200);
  const status = ann.user_status || {};
  const needsAck = Boolean(ann.require_acknowledgement) && !status.acknowledged_at;
  const needsRead = !status.read_at;

  const esc = escapeForModalHtml;

  banner.innerHTML = `
    <div class="announcement-banner-content">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span class="announcement-severity-badge severity-${esc(ann.severity || "info")}">${esc(formatSeverityLabel(ann.severity))}</span>
        <span class="announcement-banner-title">${esc(ann.title)}</span>
      </div>
      <div class="announcement-banner-body">${esc(bodyPreview)}</div>
    </div>
    <div class="announcement-banner-actions">
      ${needsAck
        ? `<button class="btn btn-primary" data-banner-action="acknowledge" data-ann-id="${esc(ann.id)}">${t("announcements.acknowledge")}</button>`
        : needsRead
          ? `<button class="btn" data-banner-action="read" data-ann-id="${esc(ann.id)}">${t("announcements.mark_read")}</button>`
          : ""}
      <button class="btn" data-banner-action="view" data-ann-id="${esc(ann.id)}" data-track-open="${ann.track_open ? "1" : "0"}">${t("announcements.view")}</button>
      <button class="announcement-banner-close" data-banner-action="dismiss" data-ann-id="${esc(ann.id)}" title="${t("announcements.dismiss")}">✕</button>
    </div>
  `;
}
