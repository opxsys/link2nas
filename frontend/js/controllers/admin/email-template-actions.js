import { saveEmailTemplate, previewEmailTemplate, resetEmailTemplate } from "../../api.js";
import { t } from "../../i18n/index.js";
import { showConfirmModal } from "../../ui/modals.js";
import { showAdminFeedback } from "./feedback.js";
import {
  getEmailTemplateBtns,
  setEmailTemplateBtnsDisabled,
  updateEmailTemplateCustomBadge,
  showEmailTemplatePreview,
  hideEmailTemplatePreview,
  insertAtCursor,
  loadEmailTemplateIntoPanel,
} from "./email-templates.js";

export async function handleEmailTemplateAction(action, button) {
  if (action === "insert-template-variable") {
    const variable = button.dataset.variable;
    if (!variable) return true;
    const textarea = document.getElementById("email-template-body");
    if (!textarea) return true;
    insertAtCursor(textarea, `{${variable}}`);
    return true;
  }

  if (action === "email-template-save") {
    const key = document.getElementById("email-template-key-select")?.value;
    const lang = document.getElementById("email-template-lang-select")?.value;
    const subject = document.getElementById("email-template-subject")?.value || "";
    const body = document.getElementById("email-template-body")?.value || "";
    if (!key || !lang) return true;

    const btns = getEmailTemplateBtns();
    setEmailTemplateBtnsDisabled(btns, true);
    try {
      const saved = await saveEmailTemplate(key, lang, { subject_template: subject, body_template: body });
      updateEmailTemplateCustomBadge(saved.is_custom);
      showAdminFeedback("email-templates", t("admin.email_templates.saved"), "success");
    } catch (error) {
      showAdminFeedback("email-templates", error.message || t("admin.email_templates.save_error"), "error");
    } finally {
      setEmailTemplateBtnsDisabled(btns, false);
    }
    return true;
  }

  if (action === "email-template-preview") {
    const key = document.getElementById("email-template-key-select")?.value;
    const lang = document.getElementById("email-template-lang-select")?.value;
    const subject = document.getElementById("email-template-subject")?.value || "";
    const body = document.getElementById("email-template-body")?.value || "";
    if (!key || !lang) return true;

    const btns = getEmailTemplateBtns();
    setEmailTemplateBtnsDisabled(btns, true);
    hideEmailTemplatePreview();
    try {
      const result = await previewEmailTemplate(key, lang, { subject_template: subject, body_template: body });
      showEmailTemplatePreview(result);
    } catch (error) {
      showAdminFeedback("email-templates", error.message || t("admin.email_templates.preview_error"), "error");
    } finally {
      setEmailTemplateBtnsDisabled(btns, false);
    }
    return true;
  }

  if (action === "email-template-reset") {
    const key = document.getElementById("email-template-key-select")?.value;
    const lang = document.getElementById("email-template-lang-select")?.value;
    if (!key || !lang) return true;

    const confirmed = await showConfirmModal({
      title: t("admin.email_templates.reset"),
      message: t("admin.email_templates.reset_confirm"),
      confirmLabel: t("admin.email_templates.reset"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return true;

    const btns = getEmailTemplateBtns();
    setEmailTemplateBtnsDisabled(btns, true);
    try {
      await resetEmailTemplate(key, lang);
      await loadEmailTemplateIntoPanel(key, lang);
      showAdminFeedback("email-templates", t("admin.email_templates.reset_done"), "success");
    } catch (error) {
      showAdminFeedback("email-templates", error.message || t("admin.email_templates.reset_error"), "error");
    } finally {
      setEmailTemplateBtnsDisabled(btns, false);
    }
    return true;
  }

  return false;
}
