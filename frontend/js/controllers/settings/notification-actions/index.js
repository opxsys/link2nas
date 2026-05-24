import { handleNotificationFormAction } from "./form-actions.js";
import { handleNotificationToggleAction } from "./toggle-actions.js";
import { handleNotificationDeleteAction } from "./delete-actions.js";
import { handleNotificationTestAction } from "./test-actions.js";

export async function handleNotificationAction(action, button) {
  if (handleNotificationFormAction(action, button)) return true;
  if (await handleNotificationToggleAction(action, button)) return true;
  if (await handleNotificationDeleteAction(action, button)) return true;
  if (await handleNotificationTestAction(action, button)) return true;

  return false;
}
