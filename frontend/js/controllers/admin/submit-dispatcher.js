import { handleSettingsSubmit } from "./settings-submit.js";
import { handleUserSubmit } from "./user-submit.js";
import { handleAnnouncementSubmit } from "./announcement-submit.js";

export async function handleAdminSubmit(form) {

  if (await handleSettingsSubmit(form)) return;
  if (await handleUserSubmit(form)) return;
  if (await handleAnnouncementSubmit(form)) return;

}
