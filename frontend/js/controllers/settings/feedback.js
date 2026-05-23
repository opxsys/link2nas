import { showAppMessage } from "../../utils.js";

function showSettingsFeedback(elementId, message, type = "info") {
  const el = document.getElementById(elementId);
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `${elementId} ${elementId}-${type}`;
  el.hidden = false;
}

export function showApiKeyFeedback(message, type = "info") {
  showSettingsFeedback("api-key-feedback", message, type);
}

export function showProviderFeedback(message, type = "info") {
  showSettingsFeedback("provider-feedback", message, type);
}

export function showDestinationFeedback(message, type = "info") {
  showSettingsFeedback("destination-feedback", message, type);
}

export function showNotificationFeedback(message, type = "info") {
  showSettingsFeedback("notification-feedback", message, type);
}
