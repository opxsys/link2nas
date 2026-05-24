import { t } from "../../i18n/index.js";
import { escapeForModalHtml } from "./utils.js";

export function showSecretModal({
  title = t("modal.secret_title"),
  message = "",
  secret = "",
  copyLabel = t("common.copy"),
  closeLabel = t("common.close"),
} = {}) {
  return new Promise((resolve) => {
    const modal = document.getElementById("app-modal");
    const titleEl = document.getElementById("app-modal-title");
    const bodyEl = document.getElementById("app-modal-body");
    const cancelBtn = document.getElementById("app-modal-cancel");
    const confirmBtn = document.getElementById("app-modal-confirm");

    if (!modal || !titleEl || !bodyEl || !cancelBtn || !confirmBtn) {
      window.prompt(message || title, secret);
      resolve(false);
      return;
    }

    titleEl.textContent = title;

    bodyEl.innerHTML = `
      ${message ? `<p class="muted">${escapeForModalHtml(message)}</p>` : ""}
      <div class="code-block" style="margin-top:12px;">${escapeForModalHtml(secret)}</div>
    `;

    cancelBtn.textContent = closeLabel;
    confirmBtn.textContent = copyLabel;

    confirmBtn.classList.remove("btn-danger");
    confirmBtn.classList.add("btn-primary");

    modal.hidden = false;

    const cleanup = () => {
      modal.hidden = true;

      cancelBtn.removeEventListener("click", onClose);
      confirmBtn.removeEventListener("click", onCopy);
      modal.removeEventListener("click", onBackdropClick);
      document.removeEventListener("keydown", onKeyDown);
    };

    const onClose = () => {
      cleanup();
      resolve(false);
    };

    const onCopy = async () => {
      try {
        await navigator.clipboard.writeText(secret);
        const orig = confirmBtn.textContent;
        confirmBtn.textContent = t("settings.api_keys.modal_copy_done");
        confirmBtn.disabled = true;
        setTimeout(() => {
          confirmBtn.textContent = orig;
          confirmBtn.disabled = false;
          cleanup();
          resolve(true);
        }, 1500);
      } catch {
        window.prompt(t("modal.secret_manual_copy"), secret);
      }
    };

    const onBackdropClick = (event) => {
      if (event.target === modal) {
        onClose();
      }
    };

    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    cancelBtn.addEventListener("click", onClose);
    confirmBtn.addEventListener("click", onCopy);
    modal.addEventListener("click", onBackdropClick);
    document.addEventListener("keydown", onKeyDown);

    confirmBtn.focus();
  });
}
