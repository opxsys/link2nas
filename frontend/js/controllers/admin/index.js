import { loadAdminData } from "./load-data.js";
import { renderLoadedAdmin } from "./render-admin.js";
import { showAdminFeedback } from "./feedback.js";
import { getFilteredAdminUsers, bindAdminUsersFilters } from "./users-filters.js";
import { loadEmailTemplateIntoPanel, initEmailTemplatesPanel } from "./email-templates.js";
import { loadAntiAbuseSection } from "./anti-abuse.js";

export { switchAdminTab } from "./tabs.js";
export { updateUserCreationModeFields } from "./render-admin.js";
export { handleAdminSubmit } from "./submit-dispatcher.js";
export { handleAdminClick } from "./click-dispatcher.js";
export { showAdminFeedback, getFilteredAdminUsers, bindAdminUsersFilters, loadEmailTemplateIntoPanel, initEmailTemplatesPanel, loadAntiAbuseSection };

export async function loadAdmin() {
  const data = await loadAdminData();
  await renderLoadedAdmin(data);
}
