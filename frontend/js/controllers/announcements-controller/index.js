import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { showAppMessage } from "../../utils.js";
import {
  listActiveAnnouncements,
  openAnnouncement,
  readAnnouncement,
  acknowledgeAnnouncement,
} from "../../api.js";
import { renderAnnouncementsPage } from "../../render/announcements.js";
import { escapeForModalHtml } from "../../ui/modals.js";
import { loadAdmin, switchAdminTab } from "../admin-controller.js";

let _setActivePage;

export function initAnnouncements({ setActivePage }) {
  _setActivePage = setActivePage;
}

const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };

function formatSeverityLabel(severity) {
  if (severity === "critical") return t("admin.announcements.severity_critical");
  if (severity === "warning") return t("admin.announcements.severity_warning");
  return t("admin.announcements.severity_info");
}

function announcementNeedsAttention(ann) {
  if (Boolean(ann.require_acknowledgement)) return !ann.user_status?.acknowledged_at;
  return !ann.user_status?.read_at;
}

function getAnnouncementsUnreadCount(announcements) {
  return (announcements || []).filter(announcementNeedsAttention).length;
}

async function refreshAnnouncementsState() {
  try {
    const announcements = await listActiveAnnouncements();
    state.announcements = Array.isArray(announcements) ? announcements : [];
  } catch {
    // non-critical
  }
  renderAnnouncementBanner(pickBannerAnnouncement(state.announcements));
  updateAnnouncementBadge(state.announcements);
  if (state.activePage === "announcements") {
    renderAnnouncementsPage(state.announcements, state.currentUser?.role === "super_admin");
  }
}

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

export function updateAnnouncementBadge(announcements) {
  const badge = document.getElementById("announcements-badge");
  if (!badge) return;
  const count = getAnnouncementsUnreadCount(announcements);
  if (count > 0) {
    badge.textContent = count > 99 ? "99+" : String(count);
    badge.hidden = false;
  } else {
    badge.hidden = true;
  }
}

export async function loadAnnouncements() {
  try {
    const announcements = await listActiveAnnouncements();
    state.announcements = Array.isArray(announcements) ? announcements : [];
  } catch {
    state.announcements = [];
  }

  renderAnnouncementsPage(state.announcements, state.currentUser?.role === "super_admin");
  updateAnnouncementBadge(state.announcements);
  renderAnnouncementBanner(pickBannerAnnouncement(state.announcements));

  // silently track opens for applicable announcements
  for (const ann of state.announcements) {
    if (ann.track_open && !(ann.user_status?.opened_at)) {
      openAnnouncement(ann.id).catch(() => {});
    }
  }
}

export async function loadAndRenderBanner() {
  try {
    const announcements = await listActiveAnnouncements();
    state.announcements = Array.isArray(announcements) ? announcements : [];
    const top = pickBannerAnnouncement(state.announcements);
    renderAnnouncementBanner(top);
    updateAnnouncementBadge(state.announcements);
  } catch {
    // banner is non-critical — silently ignore
  }
}

export function bindBannerEvents() {
  const banner = document.getElementById("announcement-banner");
  if (!banner) return;

  banner.addEventListener("click", async (event) => {
    const btn = event.target.closest("[data-banner-action]");
    if (!btn) return;

    const bannerAction = btn.dataset.bannerAction;
    const annId = btn.dataset.annId;
    if (!annId) return;

    if (bannerAction === "dismiss") {
      if (!state.dismissedAnnouncementBannerIds.includes(annId)) {
        state.dismissedAnnouncementBannerIds.push(annId);
      }
      renderAnnouncementBanner(pickBannerAnnouncement(state.announcements));
      return;
    }

    if (bannerAction === "view") {
      _setActivePage("announcements");
      await loadAnnouncements();
      return;
    }

    if (bannerAction === "read") {
      try {
        await readAnnouncement(annId);
        await refreshAnnouncementsState();
      } catch (error) {
        showAppMessage(error.message || t("messages.admin_action_error"), "error");
      }
      return;
    }

    if (bannerAction === "acknowledge") {
      try {
        await acknowledgeAnnouncement(annId);
        await refreshAnnouncementsState();
      } catch (error) {
        showAppMessage(error.message || t("messages.admin_action_error"), "error");
      }
      return;
    }
  });
}

export function bindAnnouncementsPageEvents() {
  document.getElementById("announcements-page")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-ann-action]");
    if (!button) return;

    const annAction = button.dataset.annAction;

    if (annAction === "goto-create-announcement") {
      _setActivePage("admin");
      await loadAdmin();
      state.activeAdminTab = "announcements";
      switchAdminTab("announcements");
      const createBlock = document.querySelector('[data-admin-panel="announcements"] .admin-create-user-block');
      if (createBlock) createBlock.open = true;
      return;
    }

    const annId = button.dataset.annId;
    if (!annId) return;

    button.disabled = true;
    try {
      if (annAction === "read") {
        await readAnnouncement(annId);
      } else if (annAction === "acknowledge") {
        await acknowledgeAnnouncement(annId);
      }
      await loadAnnouncements();
    } catch (error) {
      showAppMessage(error.message || t("messages.admin_action_error"), "error");
    } finally {
      button.disabled = false;
    }
  });
}
