import { handleUserStatusAction } from "./user-actions/status-actions.js";
import { handleUserLinkAction } from "./user-actions/link-actions.js";
import { handleUserEmailAction } from "./user-actions/email-actions.js";

export async function handleUserAction(action, button) {
  const id = button.dataset.id;

  if (action === "toggle-user-edit") {
    const card = button.closest("[data-user-id]");
    const editContent = card?.querySelector(".admin-user-edit-content");
    if (editContent) {
      editContent.hidden = !editContent.hidden;
      button.classList.toggle("is-active", !editContent.hidden);
    }
    return true;
  }

  if (await handleUserStatusAction(action, id)) {
    return true;
  }

  if (await handleUserLinkAction(action, id)) {
    return true;
  }

  if (await handleUserEmailAction(action, id)) {
    return true;
  }

  return false;
}
