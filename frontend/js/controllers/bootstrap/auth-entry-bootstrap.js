import { state } from "../../state.js";
import { getSetupStatus, getPublicAppInfo } from "../../api.js";
import { renderSetupForm, renderLoginForm } from "../../render/auth.js";
import { bindAuthEvents } from "../auth-controller.js";

export async function renderAuthEntryPoint() {
  const setupStatus = await getSetupStatus();

  if (setupStatus.setup_required) {
    renderSetupForm();
    bindAuthEvents();
    return;
  }

  let appInfoEmailAvailable = true;
  try {
    const appInfo = await getPublicAppInfo();
    state.appInfo = appInfo;
    appInfoEmailAvailable = appInfo?.email_sending_available ?? true;
  } catch {
    // Non bloquant — on affiche le bouton magic login par défaut
  }

  renderLoginForm(appInfoEmailAvailable);
  bindAuthEvents();
}
