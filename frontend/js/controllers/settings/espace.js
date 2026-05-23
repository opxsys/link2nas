import { t } from "../../i18n/index.js";
import { getMyPublicSpace, cleanMyPublicSpace } from "../../api.js";
import { renderEspaceContent } from "../../render/settings.js";
import { showConfirmModal } from "../../ui/modals.js";

export async function loadEspace() {
  const contentEl = document.getElementById("espace-content");
  if (!contentEl) return;

  try {
    const data = await getMyPublicSpace();
    contentEl.innerHTML = renderEspaceContent(data);

    const copyBtn = contentEl.querySelector("#espace-copy-btn");
    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        const url = copyBtn.dataset.url || "";
        try {
          await navigator.clipboard.writeText(url);
          copyBtn.textContent = "✓";
          setTimeout(() => { copyBtn.textContent = "⧉"; }, 2000);
        } catch {
          // clipboard not available
        }
      });
    }

    const cleanupBtn = contentEl.querySelector("#espace-cleanup-btn");
    if (cleanupBtn) {
      cleanupBtn.addEventListener("click", async () => {
        const ok = await showConfirmModal({
          title: t("settings.espace.cleanup_confirm_title"),
          message: t("settings.espace.cleanup_confirm"),
          confirmLabel: t("settings.espace.cleanup_btn"),
          cancelLabel: t("common.cancel"),
          danger: true,
        });
        if (!ok) return;
        const feedbackEl = contentEl.querySelector("#espace-feedback");
        try {
          cleanupBtn.disabled = true;
          const result = await cleanMyPublicSpace();
          if (feedbackEl) {
            feedbackEl.hidden = false;
            feedbackEl.className = "form-feedback success";
            feedbackEl.textContent = t("settings.espace.cleanup_ok").replace("{count}", result.deleted_count ?? 0);
          }
          await loadEspace();
        } catch (err) {
          if (feedbackEl) {
            feedbackEl.hidden = false;
            feedbackEl.className = "form-feedback error";
            feedbackEl.textContent = t("settings.espace.cleanup_error");
          }
        } finally {
          if (cleanupBtn) cleanupBtn.disabled = false;
        }
      });
    }
  } catch {
    if (contentEl) {
      contentEl.innerHTML = `<p class="muted">${t("settings.espace.error")}</p>`;
    }
  }
}
