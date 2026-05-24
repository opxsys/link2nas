import { state } from "../../state.js";
import { listActiveAnnouncements, openAnnouncement } from "../../api.js";
import { renderAnnouncementsPage } from "../../render/announcements.js";
import { pickBannerAnnouncement, renderAnnouncementBanner } from "./banner.js";
import { getAnnouncementsUnreadCount } from "./helpers.js";

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
