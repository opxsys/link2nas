import { clearToken } from "../../core/session.js";
import { state } from "../../state.js";
import { logout } from "../../api.js";
import { closeNavDrawer, updateAuthVisibility } from "../navigation-controller.js";

export function bindSessionEvents() {
  document.getElementById("logout-btn")?.addEventListener("click", async () => {
    closeNavDrawer();

    try {
      await logout();
    } catch {}

    state.currentUser = null;
    updateAuthVisibility();
    clearToken();
    location.reload();
  });
}
