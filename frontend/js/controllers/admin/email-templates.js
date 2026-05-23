import { getEmailTemplate } from "../../api.js";
import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import { showAdminFeedback } from "./feedback.js";

const EMAIL_TEMPLATE_KEYS_ORDER = [
  "invitation",
  "password_reset",
  "email_verification",
  "magic_login",
  "smtp_test",
  "announcement",
  "notification_test",
  "notification_event",
];

export function getEmailTemplateBtns() {
  return [
    document.getElementById("email-template-save-btn"),
    document.getElementById("email-template-preview-btn"),
    document.getElementById("email-template-reset-btn"),
  ].filter(Boolean);
}

export function setEmailTemplateBtnsDisabled(btns, disabled) {
  btns.forEach((btn) => { btn.disabled = disabled; });
}

export function updateEmailTemplateCustomBadge(isCustom) {
  const badge = document.getElementById("email-template-custom-badge");
  if (!badge) return;
  badge.textContent = isCustom ? t("admin.email_templates.custom") : t("admin.email_templates.default");
  badge.className = isCustom ? "badge badge-premium" : "badge";
}

export function showEmailTemplatePreview(result) {
  const block = document.getElementById("email-template-preview-block");
  const subjectEl = document.getElementById("email-template-preview-subject");
  const bodyEl = document.getElementById("email-template-preview-body");
  const sampleEl = document.getElementById("email-template-preview-sample");
  if (!block || !subjectEl || !bodyEl) return;

  subjectEl.textContent = result.subject || "";
  bodyEl.textContent = result.body || "";
  if (sampleEl && result.sample_values) {
    sampleEl.textContent = JSON.stringify(result.sample_values, null, 2);
  }
  block.hidden = false;
}

export function hideEmailTemplatePreview() {
  const block = document.getElementById("email-template-preview-block");
  if (block) block.hidden = true;
}

export function insertAtCursor(textarea, text) {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  textarea.value = textarea.value.slice(0, start) + text + textarea.value.slice(end);
  textarea.selectionStart = textarea.selectionEnd = start + text.length;
  textarea.focus();
}

export async function loadEmailTemplateIntoPanel(key, lang) {
  const feedbackEl = document.getElementById("admin-email-templates-feedback");
  if (feedbackEl) feedbackEl.hidden = true;
  hideEmailTemplatePreview();

  const btns = getEmailTemplateBtns();
  setEmailTemplateBtnsDisabled(btns, true);

  try {
    const tmpl = await getEmailTemplate(key, lang);

    const subjectInput = document.getElementById("email-template-subject");
    const bodyTextarea = document.getElementById("email-template-body");
    if (subjectInput) subjectInput.value = tmpl.subject_template || "";
    if (bodyTextarea) bodyTextarea.value = tmpl.body_template || "";

    updateEmailTemplateCustomBadge(tmpl.is_custom);

    const variablesContainer = document.getElementById("email-template-variables");
    const variablesBlock = document.getElementById("email-template-variables-block");
    const variables = Array.isArray(tmpl.available_variables) ? tmpl.available_variables : [];

    if (variables.length > 0 && variablesContainer && variablesBlock) {
      variablesContainer.innerHTML = variables
        .map((v) => `<button type="button" class="email-template-variable-badge" data-action="insert-template-variable" data-variable="${v}">{${v}}</button>`)
        .join("");
      variablesBlock.hidden = false;
    } else if (variablesBlock) {
      variablesBlock.hidden = true;
    }

    const keySelect = document.getElementById("email-template-key-select");
    const langSelect = document.getElementById("email-template-lang-select");
    if (keySelect) keySelect.value = key;
    if (langSelect) langSelect.value = lang;
  } catch (error) {
    showAdminFeedback("email-templates", error.message || t("admin.email_templates.load_error"), "error");
  } finally {
    setEmailTemplateBtnsDisabled(btns, false);
  }
}

export async function initEmailTemplatesPanel() {
  const keySelect = document.getElementById("email-template-key-select");
  if (!keySelect) return;

  if (!keySelect.options.length) {
    keySelect.innerHTML = EMAIL_TEMPLATE_KEYS_ORDER
      .map((key) => `<option value="${key}">${t(`admin.email_templates.key_${key}`)}</option>`)
      .join("");
  }

  const langSelect = document.getElementById("email-template-lang-select");
  const currentKey = keySelect.value || EMAIL_TEMPLATE_KEYS_ORDER[0];
  const currentLang = langSelect?.value || (state.language === "fr" ? "fr" : "en");
  if (langSelect) langSelect.value = currentLang;

  await loadEmailTemplateIntoPanel(currentKey, currentLang);
}
