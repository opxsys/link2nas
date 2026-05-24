import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { showAppMessage } from "../../utils.js";
import {
  listActiveAnnouncements,
  readAnnouncement,
  acknowledgeAnnouncement,
} from "../../api.js";
import { renderAnnouncementsPage } from "../../render/announcements.js";
import { loadAdmin, switchAdminTab } from "../admin-controller.js";
import { pickBannerAnnouncement, renderAnnouncementBanner } from "./banner.js";
import { updateAnnouncementBadge, loadAnnouncements } from "./loading.js";
export { pickBannerAnnouncement, renderAnnouncementBanner } from "./banner.js";
export { updateAnnouncementBadge, loadAnnouncements, loadAndRenderBanner } from "./loading.js";

let _setActivePage;

export function initAnnouncements({ setActivePage }) {
  _setActivePage = setActivePage;
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
