import { bindSetupAuthEvents } from "./setup-actions.js";
import { bindLoginAuthEvents } from "./login-actions.js";
import { bindMagicLoginAuthEvents } from "./magic-login-actions.js";
import { bindPublicTokenAuthEvents } from "./public-token-actions.js";
import { bindForcedPasswordChangeAuthEvents } from "./password-change-actions.js";
export { validatePasswordConfirmation, validateForcedPasswordChangeForm } from "../validation.js";

let _enterMainApplication;
let _hideAdminIfNeeded;
let _updateAuthVisibility;
let _clearPublicAccountUrl;
let _applyCurrentUserTheme;

export function initAuth({
  enterMainApplication,
  hideAdminIfNeeded,
  updateAuthVisibility,
  clearPublicAccountUrl,
  applyCurrentUserTheme,
}) {
  _enterMainApplication = enterMainApplication;
  _hideAdminIfNeeded = hideAdminIfNeeded;
  _updateAuthVisibility = updateAuthVisibility;
  _clearPublicAccountUrl = clearPublicAccountUrl;
  _applyCurrentUserTheme = applyCurrentUserTheme;
}

export function bindAuthEvents() {
  bindSetupAuthEvents({ bindAuthEvents });
  bindLoginAuthEvents({
    applyCurrentUserTheme: _applyCurrentUserTheme,
    updateAuthVisibility: _updateAuthVisibility,
    hideAdminIfNeeded: _hideAdminIfNeeded,
    enterMainApplication: _enterMainApplication,
    bindAuthEvents,
  });

  bindMagicLoginAuthEvents({ bindAuthEvents });
  bindPublicTokenAuthEvents({
    bindAuthEvents,
    clearPublicAccountUrl: _clearPublicAccountUrl,
  });

  bindForcedPasswordChangeAuthEvents({
    applyCurrentUserTheme: _applyCurrentUserTheme,
    updateAuthVisibility: _updateAuthVisibility,
    hideAdminIfNeeded: _hideAdminIfNeeded,
    enterMainApplication: _enterMainApplication,
  });
}
