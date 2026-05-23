import {
  saveAdminGeneralSettings,
  saveAdminSmtpSettings,
  saveAdminSecuritySettings,
  saveAdminCleanupSettings,
  saveAdminRestartCooldowns,
  saveAdminRuntimeSettings,
} from "../../api.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { showAdminFeedback } from "./feedback.js";
import {
  buildSmtpSettingsPayload,
  buildSecuritySettingsPayload,
  buildCleanupSettingsPayload,
  buildRestartCooldownsPayload,
  buildRuntimeSettingsPayload,
} from "./payloads.js";
import { loadAdmin, switchAdminTab } from "./index.js";

export async function handleSettingsSubmit(form) {
  if (form.id === "admin-general-form") {
    const payload = {
      app_name: form.app_name?.value?.trim() || "",
      app_tagline: form.app_tagline?.value?.trim() || "",
      public_base_url: form.public_base_url?.value?.trim() || "",
    };
    try {
      const saved = await saveAdminGeneralSettings(payload);
      state.generalSettings = saved;
      state.activeAdminTab = "general";
      await loadAdmin();
      switchAdminTab("general");
      showAdminFeedback("general", t("messages.admin_general_saved"), "success");
    } catch (error) {
      showAdminFeedback("general", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (form.id === "admin-smtp-form") {
    const payload = buildSmtpSettingsPayload(form);
    try {
      await saveAdminSmtpSettings(payload);
      state.activeAdminTab = "smtp";
      await loadAdmin();
      switchAdminTab("smtp");
      showAdminFeedback("smtp", t("messages.admin_smtp_saved"), "success");
    } catch (error) {
      showAdminFeedback("smtp", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (form.id === "admin-security-form") {
    const payload = buildSecuritySettingsPayload(form);
    try {
      await saveAdminSecuritySettings(payload);
      state.activeAdminTab = "security";
      await loadAdmin();
      switchAdminTab("security");
      showAdminFeedback("security", t("messages.admin_security_saved"), "success");
    } catch (error) {
      showAdminFeedback("security", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (form.id === "admin-cleanup-form") {
    const payload = buildCleanupSettingsPayload(form);
    try {
      await saveAdminCleanupSettings(payload);
      state.activeAdminTab = "cleanup";
      await loadAdmin();
      switchAdminTab("cleanup");
      showAdminFeedback("cleanup", t("messages.admin_cleanup_saved"), "success");
    } catch (error) {
      showAdminFeedback("cleanup", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (form.id === "admin-timeouts-form") {
    const payload = buildRestartCooldownsPayload(form);
    try {
      const saved = await saveAdminRestartCooldowns(payload);
      state.restartCooldowns = saved;
      state.timeoutSettings = saved;
      state.activeAdminTab = "timeouts";
      await loadAdmin();
      switchAdminTab("timeouts");
      showAdminFeedback("timeouts", t("messages.admin_timeouts_saved"), "success");
    } catch (error) {
      showAdminFeedback("timeouts", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (form.id === "admin-runtime-form") {
    const payload = buildRuntimeSettingsPayload(form);
    try {
      const saved = await saveAdminRuntimeSettings(payload);
      state.runtimeSettings = saved;
      state.activeAdminTab = "runtime";
      await loadAdmin();
      switchAdminTab("runtime");
      showAdminFeedback("runtime", t("messages.admin_runtime_saved"), "success");
    } catch (error) {
      showAdminFeedback("runtime", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  return false;
}
