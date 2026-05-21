import { showAppMessage } from "../../utils.js";

export function showAdminFeedback(section, message, type = "info") {
  const el = document.getElementById(`admin-${section}-feedback`);
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `admin-feedback admin-feedback-${type}`;
  el.hidden = false;
}
