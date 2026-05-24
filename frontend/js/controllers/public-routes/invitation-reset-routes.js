import { t } from "../../i18n/index.js";
import {
  renderInvalidToken,
  renderAcceptInvitationForm,
  renderPasswordResetForm,
} from "../../render/auth.js";
import { bindAuthEvents } from "../auth-controller.js";
import { isInviteRoute, isPasswordResetRoute } from "./route-utils.js";

export function handleInvitationRoute({ token, tokenStatus }) {
  if (!isInviteRoute()) {
    return false;
  }

  if (tokenStatus.token_type !== "invitation") {
    renderInvalidToken(t("auth.error.not_invitation_link"));
    bindAuthEvents();
    return true;
  }

  renderAcceptInvitationForm(token, tokenStatus);
  bindAuthEvents();
  return true;
}

export function handlePasswordResetRoute({ token, tokenStatus }) {
  if (!isPasswordResetRoute()) {
    return false;
  }

  if (tokenStatus.token_type !== "password_reset") {
    renderInvalidToken(t("auth.error.not_reset_link"));
    bindAuthEvents();
    return true;
  }

  renderPasswordResetForm(token, tokenStatus);
  bindAuthEvents();
  return true;
}
