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
