import { t } from "../i18n/index.js";
import { showAppMessage } from "../utils.js";

export function showConfirmModal({
  title = "Confirmation",
  message = "Confirmer cette action ?",
  confirmLabel = "Valider",
  cancelLabel = "Annuler",
  danger = false,
} = {}) {
  return new Promise((resolve) => {
    const modal = document.getElementById("app-modal");
    const titleEl = document.getElementById("app-modal-title");
    const bodyEl = document.getElementById("app-modal-body");
    const cancelBtn = document.getElementById("app-modal-cancel");
    const confirmBtn = document.getElementById("app-modal-confirm");

    if (!modal || !titleEl || !bodyEl || !cancelBtn || !confirmBtn) {
      resolve(window.confirm(message));
      return;
    }

    titleEl.textContent = title;
    bodyEl.textContent = message;
    cancelBtn.textContent = cancelLabel;
    confirmBtn.textContent = confirmLabel;

    confirmBtn.classList.toggle("btn-danger", danger);
    confirmBtn.classList.toggle("btn-primary", !danger);

    modal.hidden = false;

    const cleanup = () => {
      modal.hidden = true;

      cancelBtn.removeEventListener("click", onCancel);
      confirmBtn.removeEventListener("click", onConfirm);
      modal.removeEventListener("click", onBackdropClick);
      document.removeEventListener("keydown", onKeyDown);
    };

    const onCancel = () => {
      cleanup();
      resolve(false);
    };

    const onConfirm = () => {
      cleanup();
      resolve(true);
    };

    const onBackdropClick = (event) => {
      if (event.target === modal) {
        onCancel();
      }
    };

    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onCancel();
      }
    };

    cancelBtn.addEventListener("click", onCancel);
    confirmBtn.addEventListener("click", onConfirm);
    modal.addEventListener("click", onBackdropClick);
    document.addEventListener("keydown", onKeyDown);

    cancelBtn.focus();
  });
}

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

export function escapeForModalHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function formatDateForModal(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

export function toAbsoluteAppUrl(link) {
  const value = String(link || "").trim();
  if (!value) return "";

  if (/^https?:\/\//i.test(value)) {
    return value;
  }

  if (value.startsWith("/")) {
    return `${window.location.origin}${value}`;
  }

  return `${window.location.origin}/${value}`;
}
