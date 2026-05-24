import { handleEmailTemplateAction } from "./email-template-actions.js";
import { handleAntiAbuseAction } from "./anti-abuse-actions.js";
import { handleUserAction } from "./user-actions.js";
import { handleSystemAction } from "./system-actions.js";
import { handleAnnouncementAction } from "./announcement-actions.js";

export async function handleAdminClick(button) {
  const action = button.dataset.action;
  const id = button.dataset.id;

  if (await handleEmailTemplateAction(action, button)) return;
  if (await handleAntiAbuseAction(action, button)) return;
  if (await handleUserAction(action, button)) return;
  if (await handleSystemAction(action, button)) return;
  if (await handleAnnouncementAction(action, button)) return;

}
