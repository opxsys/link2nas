import { getAdminAntiAbuse } from "../../api.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { renderAntiAbuseSection } from "../../render/admin.js";
import { showAdminFeedback } from "./feedback.js";

export async function loadAntiAbuseSection() {
  const contentEl = document.getElementById("admin-anti-abuse-content");
  const feedbackEl = document.getElementById("admin-anti-abuse-feedback");
  if (!contentEl) return;

  try {
    const data = await getAdminAntiAbuse();
    state.antiAbuseData = data;
    contentEl.innerHTML = renderAntiAbuseSection(data);
    if (feedbackEl) feedbackEl.hidden = true;
  } catch (error) {
    showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
  }
}
