export function openModal({ title, bodyHtml, confirmLabel = "Valider", cancelLabel = "Annuler" }) {
  return new Promise((resolve) => {
    const modal = document.getElementById("app-modal");
    const titleEl = document.getElementById("app-modal-title");
    const bodyEl = document.getElementById("app-modal-body");
    const confirmBtn = document.getElementById("app-modal-confirm");
    const cancelBtn = document.getElementById("app-modal-cancel");

    if (!modal || !titleEl || !bodyEl || !confirmBtn || !cancelBtn) {
      resolve(null);
      return;
    }

    titleEl.textContent = title;
    bodyEl.innerHTML = bodyHtml;
    confirmBtn.textContent = confirmLabel;
    cancelBtn.textContent = cancelLabel;

    modal.hidden = false;

    const cleanup = (value) => {
      modal.hidden = true;
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      modal.onclick = null;
      resolve(value);
    };

    confirmBtn.onclick = () => cleanup(true);
    cancelBtn.onclick = () => cleanup(false);

    modal.onclick = (event) => {
      if (event.target === modal) {
        cleanup(false);
      }
    };
  });
}

export async function confirmModal(title, message, confirmLabel = "Confirmer") {
  return openModal({
    title,
    bodyHtml: `<p class="muted">${message}</p>`,
    confirmLabel,
  });
}

export function normalizeSelectOption(option) {
  if (typeof option === "object" && option !== null) {
    return {
      value: String(option.value ?? option.id ?? ""),
      label: String(option.label ?? option.name ?? option.value ?? option.id ?? ""),
    };
  }

  return {
    value: String(option),
    label: String(option),
  };
}

export async function selectModal(title, label, values, defaultValue = "") {
  if (!values.length) {
    return null;
  }

  const normalizedOptions = values.map(normalizeSelectOption);
  const defaultOptionValue = typeof defaultValue === "object" && defaultValue !== null
    ? String(defaultValue.value ?? defaultValue.id ?? "")
    : String(defaultValue || "");

  const optionsHtml = normalizedOptions.map((option) => `
    <option value="${option.value}" ${option.value === defaultOptionValue ? "selected" : ""}>
      ${option.label}
    </option>
  `).join("");

  const confirmed = await openModal({
    title,
    bodyHtml: `
      <label class="form-grid">
        <span>${label}</span>
        <select id="app-modal-select">
          ${optionsHtml}
        </select>
      </label>
    `,
    confirmLabel: "Valider",
  });

  if (!confirmed) {
    return null;
  }

  return document.getElementById("app-modal-select")?.value || null;
}

export function getDestinationLabel(destination) {
  const name = String(destination?.name || destination?.destination_profile_name || "").trim();
  const type = String(destination?.destination_type || destination?.destination_name || "").trim();

  if (name && type) return `${name} (${type})`;
  return name || type || String(destination?.id || "");
}

export async function selectDestinationConfigModal(title, label, destinations, defaultId = "") {
  if (!destinations.length) return null;

  const optionsHtml = destinations.map((destination) => {
    const id = String(destination.id || "");
    return `
      <option value="${id}" ${id === defaultId ? "selected" : ""}>
        ${getDestinationLabel(destination)}
      </option>
    `;
  }).join("");

  const confirmed = await openModal({
    title,
    bodyHtml: `
      <label class="form-grid">
        <span>${label}</span>
        <select id="app-modal-select">
          ${optionsHtml}
        </select>
      </label>
    `,
    confirmLabel: "Valider",
  });

  if (!confirmed) return null;

  return document.getElementById("app-modal-select")?.value || null;
}
