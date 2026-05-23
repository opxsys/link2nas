import { getToken } from "../../core/session.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import {
  testAdminSmtpSettings,
  runAdminCleanup,
  getAdminMaintenanceStatus,
  getAdminNotificationDispatcherStatus,
  runAdminNotificationDispatcherOnce,
} from "../../api.js";
import { renderLoginForm } from "../../render/auth.js";
import { showAppMessage } from "../../utils.js";
import { showConfirmModal } from "../../ui/modals.js";
import { bindAuthEvents } from "../auth-controller.js";
import { showAdminFeedback } from "./feedback.js";
import { formatCleanupResult } from "./payloads.js";
import { loadAdmin, switchAdminTab } from "./index.js";

export async function handleSystemAction(action, button) {
  if (action === "test-admin-smtp") {
    try {
      const result = await testAdminSmtpSettings();
      showAdminFeedback("smtp", result.message || t("messages.admin_smtp_test_sent"), "success");
    } catch (error) {
      showAdminFeedback("smtp", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "run-admin-cleanup") {
    const confirmed = await showConfirmModal({
      title: t("admin.cleanup.confirm_title"),
      message: t("admin.cleanup.confirm_message"),
      confirmLabel: t("admin.cleanup.confirm_run"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return true;

    try {
      const result = await runAdminCleanup();
      state.activeAdminTab = "cleanup";
      await loadAdmin();
      switchAdminTab("cleanup");
      showAdminFeedback(
        "cleanup",
        `${t("messages.admin_cleanup_run")} ${formatCleanupResult(result)}`,
        "success"
      );
    } catch (error) {
      showAdminFeedback("cleanup", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "refresh-admin-maintenance") {
    const token = getToken();

    if (!token && !state.currentUser?.single_user_mode) {
      showAppMessage(t("messages.session_expired"), "error");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
      return true;
    }

    try {
      const result = await getAdminMaintenanceStatus();
      state.maintenanceStatus = result;
      state.activeAdminTab = "maintenance";
      await loadAdmin();
      switchAdminTab("maintenance");
      showAdminFeedback(
        "maintenance",
        t("messages.admin_maintenance_refreshed"),
        result.ok ? "success" : "info"
      );
    } catch (error) {
      showAdminFeedback("maintenance", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "run-notification-dispatcher-now") {
    const limit = Number(
      document.querySelector("[name='notification_dispatcher_limit']")?.value || 25
    );
    try {
      const result = await runAdminNotificationDispatcherOnce(limit);
      state.activeAdminTab = "runtime";
      await loadAdmin();
      switchAdminTab("runtime");
      showAdminFeedback(
        "runtime",
        `${t("messages.admin_dispatcher_run")} processed=${result.processed || 0}, sent=${result.sent || 0}, retrying=${result.retrying || 0}, failed=${result.failed || 0}`,
        result.errors?.length ? "info" : "success"
      );
    } catch (error) {
      showAdminFeedback("runtime", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  if (action === "refresh-notification-dispatcher-status") {
    try {
      const result = await getAdminNotificationDispatcherStatus();
      state.activeAdminTab = "runtime";
      await loadAdmin();
      switchAdminTab("runtime");
      showAdminFeedback(
        "runtime",
        result.last_error ? result.last_error : t("messages.admin_dispatcher_refreshed"),
        result.last_error ? "info" : "success"
      );
    } catch (error) {
      showAdminFeedback("runtime", error.message || t("messages.admin_action_error"), "error");
    }
    return true;
  }

  return false;
}
