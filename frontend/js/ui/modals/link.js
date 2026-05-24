import { t } from "../../i18n/index.js";
import { showAppMessage } from "../../utils.js";
import { escapeForModalHtml, formatDateForModal, toAbsoluteAppUrl } from "./utils.js";

export function showLinkModal({
  title = t("modal.link_title"),
  message = "",
  link = "",
  expiresAt = null,
  copyLabel = t("common.copy"),
  closeLabel = t("common.close"),
} = {}) {
  return new Promise((resolve) => {
    const absoluteLink = toAbsoluteAppUrl(link);
    const modal = document.getElementById("app-modal");
    const titleEl = document.getElementById("app-modal-title");
    const bodyEl = document.getElementById("app-modal-body");
    const cancelBtn = document.getElementById("app-modal-cancel");
    const confirmBtn = document.getElementById("app-modal-confirm");

    if (!modal || !titleEl || !bodyEl || !cancelBtn || !confirmBtn) {
      window.prompt(message || title, toAbsoluteAppUrl(link));
      resolve(false);
      return;
    }

    titleEl.textContent = title;

    bodyEl.innerHTML = `
      ${message ? `<p class="muted">${escapeForModalHtml(message)}</p>` : ""}
      ${
        expiresAt
          ? `<p class="muted">${escapeForModalHtml(t("modal.expires_at", { date: formatDateForModal(expiresAt) }))}</p>`
          : ""
      }
      <div class="code-block" style="margin-top:12px;">${escapeForModalHtml(absoluteLink)}</div>
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

    const copyLink = async () => {
      try {
        await navigator.clipboard.writeText(absoluteLink);
        showAppMessage(t("messages.link_copied"), "success");
      } catch {
        window.prompt(t("modal.link_manual_copy"), absoluteLink);
      }
    };

    const onClose = () => {
      cleanup();
      resolve(false);
    };

    const onCopy = async () => {
      await copyLink();
      cleanup();
      resolve(true);
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
