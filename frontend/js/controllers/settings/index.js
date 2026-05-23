import { loadSettings, onSettingsTabChange } from "./loader.js";
export { loadSettings, onSettingsTabChange };
export { loadEspace } from "./espace.js";
import { handleAccountSubmit } from "./account-submit.js";
import { handleProwlarrSubmit } from "./prowlarr-submit.js";
import { handleProviderSubmit } from "./provider-submit.js";
import { handleDestinationSubmit } from "./destination-submit.js";
import { handleApiKeySubmit } from "./api-key-submit.js";
import { handleNotificationSubmit } from "./notification-submit.js";
import { handleApiKeyAction } from "./api-key-actions.js";
import { handleProviderAction } from "./provider-actions.js";
import { handleDestinationAction } from "./destination-actions.js";
import { handleNotificationAction } from "./notification-actions.js";
import { handleProwlarrAction } from "./prowlarr-actions.js";

export async function handleSettingsSubmit(form) {
  if (await handleAccountSubmit(form)) return;
  if (await handleProwlarrSubmit(form)) return;
  if (await handleProviderSubmit(form)) return;
  if (await handleDestinationSubmit(form)) return;
  if (await handleApiKeySubmit(form)) return;
  if (await handleNotificationSubmit(form)) return;
}

export async function handleSettingsClick(button) {
  const action = button.dataset.settingsAction || button.dataset.action;
  if (await handleApiKeyAction(action, button)) return;
  if (await handleProviderAction(action, button)) return;
  if (await handleDestinationAction(action, button)) return;
  if (await handleNotificationAction(action, button)) return;
  if (await handleProwlarrAction(action, button)) return;
}
