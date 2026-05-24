import { state } from "../../state.js";
import { hasConfiguredProwlarr } from "../../render/prowlarr.js";

export function hideAdminIfNeeded() {
  const adminButton = document.querySelector('[data-page="admin"]');
  const isSuperAdmin = state.currentUser?.role === "super_admin";

  if (adminButton) {
    adminButton.hidden = !isSuperAdmin;
  }

  if (!isSuperAdmin && state.activePage === "admin") {
    state.activePage = "jobs";
    localStorage.setItem("link2nas_active_page", "jobs");
  }
}

export function updateAuthVisibility() {
  const isAuthenticated = Boolean(state.currentUser);
  const mustChangePassword = Boolean(state.currentUser?.force_password_change);
  const isSingleUserMode = Boolean(state.currentUser?.single_user_mode);

  const mainNav = document.getElementById("main-nav");
  if (mainNav) {
    mainNav.hidden = !isAuthenticated || mustChangePassword;
  }

  const logoutButton = document.getElementById("logout-btn");
  if (logoutButton) {
    logoutButton.hidden = !isAuthenticated || isSingleUserMode;
  }
}

export function openNavDrawer() {
  const drawer = document.getElementById("nav-drawer");
  const overlay = document.getElementById("nav-drawer-overlay");
  const burgerBtn = document.getElementById("nav-burger-btn");

  if (drawer) drawer.classList.add("is-open");
  if (overlay) overlay.classList.add("is-open");
  if (burgerBtn) burgerBtn.setAttribute("aria-expanded", "true");
}

export function closeNavDrawer() {
  const drawer = document.getElementById("nav-drawer");
  const overlay = document.getElementById("nav-drawer-overlay");
  const burgerBtn = document.getElementById("nav-burger-btn");

  if (drawer) drawer.classList.remove("is-open");
  if (overlay) overlay.classList.remove("is-open");
  if (burgerBtn) burgerBtn.setAttribute("aria-expanded", "false");
}

export function updateProwlarrNavVisibility() {
  const prowlarrButton = document.querySelector('[data-page="prowlarr"]');
  if (!prowlarrButton) return;

  prowlarrButton.hidden = !hasConfiguredProwlarr();
}

export function updateLanguageSwitchUI() {
  document.querySelectorAll("#language-switch [data-lang]").forEach((button) => {
    const isActive = button.dataset.lang === state.language;
    button.classList.toggle("is-active", isActive);
  });
}

export function updateMainNavUI() {
  updateProwlarrNavVisibility();

  document.querySelectorAll("#main-nav [data-page]").forEach((button) => {
    const isActive = button.dataset.page === state.activePage;
    button.classList.toggle("is-active", isActive);
  });
}
