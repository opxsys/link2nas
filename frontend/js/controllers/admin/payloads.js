import { t } from "../../i18n/index.js";

export function getOptionalDatetimeValue(form, name) {
  const value = form[name]?.value;
  return value ? value : null;
}

export function buildSmtpSettingsPayload(form) {
  return {
    enabled: Boolean(form.enabled?.checked),
    host: form.host?.value || "",
    port: Number(form.port?.value || 587),
    username: form.username?.value || "",
    password: form.password?.value || undefined,
    from_email: form.from_email?.value || "",
    from_name: form.from_name?.value || "",
    use_tls: Boolean(form.use_tls?.checked),
    use_ssl: Boolean(form.use_ssl?.checked),
  };
}

export function buildSecuritySettingsPayload(form) {
  return {
    token_ttl: {
      invitation_ttl_hours: Number(form.invitation_ttl_hours?.value || 48),
      password_reset_ttl_hours: Number(form.password_reset_ttl_hours?.value || 2),
      magic_login_ttl_minutes: Number(form.magic_login_ttl_minutes?.value || 15),
      email_verification_ttl_hours: Number(form.email_verification_ttl_hours?.value || 24),
      session_inactivity_minutes: Number(form.session_inactivity_minutes?.value || 30),
    },
    password_policy: {
      min_length: Number(form.min_length?.value || 10),
      require_uppercase: Boolean(form.require_uppercase?.checked),
      require_lowercase: Boolean(form.require_lowercase?.checked),
      require_number: Boolean(form.require_number?.checked),
      require_special: Boolean(form.require_special?.checked),
    },
  };
}

export function buildCleanupSettingsPayload(form) {
  return {
    retention: {
      torrent_tmp_days: Number(form.torrent_tmp_days?.value || 7),
      completed_jobs_days: Number(form.completed_jobs_days?.value || 30),
      failed_jobs_days: Number(form.failed_jobs_days?.value || 30),
      cancelled_jobs_days: Number(form.cancelled_jobs_days?.value || 15),
      expired_tokens_days: Number(form.expired_tokens_days?.value || 7),
    },
  };
}

export function buildRestartCooldownsPayload(form) {
  return {
    default_seconds: Number(form.default_seconds?.value || 10),
    realdebrid_seconds: Number(form.realdebrid_seconds?.value || 60),
    alldebrid_seconds: Number(form.alldebrid_seconds?.value || 8),
  };
}

export function buildRuntimeSettingsPayload(form) {
  return {
    notifications: {
      dispatcher: {
        enabled: Boolean(form.notification_dispatcher_enabled?.checked),
        interval_seconds: Number(form.notification_dispatcher_interval_seconds?.value || 60),
        limit: Number(form.notification_dispatcher_limit?.value || 25),
      },
    },
    jobs: {
      orchestrator: {
        enabled: Boolean(form.jobs_orchestrator_enabled?.checked),
        interval_seconds: Number(form.jobs_orchestrator_interval_seconds?.value || 5),
        max_jobs_per_run: Number(form.jobs_orchestrator_max_jobs_per_run?.value || 25),
        auto_refresh_enabled: Boolean(form.jobs_orchestrator_auto_refresh_enabled?.checked),
        auto_unrestrict_enabled: Boolean(form.jobs_orchestrator_auto_unrestrict_enabled?.checked),
        auto_send_destination_enabled: Boolean(form.jobs_orchestrator_auto_send_destination_enabled?.checked),
      },
    },
    downloads: {
      local_worker: {
        enabled: Boolean(form.local_worker_enabled?.checked),
        poll_interval_seconds: Number(form.local_worker_poll_interval_seconds?.value || 5),
        max_concurrent_downloads: Number(form.local_worker_max_concurrent_downloads?.value || 1),
      },
    },
  };
}

export function buildAnnouncementPayload(form) {
  const startsAtVal = form.starts_at?.value;
  const endsAtVal = form.ends_at?.value;
  return {
    title: String(form.title?.value || "").trim(),
    body: String(form.body?.value || "").trim(),
    type: form.type?.value || "news",
    severity: form.severity?.value || "info",
    is_active: Boolean(form.is_active?.checked),
    show_as_banner: Boolean(form.show_as_banner?.checked),
    require_acknowledgement: Boolean(form.require_acknowledgement?.checked),
    track_open: Boolean(form.track_open?.checked),
    send_email: Boolean(form.send_email?.checked),
    starts_at: startsAtVal ? new Date(startsAtVal).toISOString() : null,
    ends_at: endsAtVal ? new Date(endsAtVal).toISOString() : null,
  };
}

export function formatCleanupResult(result) {
  const errors = Array.isArray(result?.temp_files_errors)
    ? result.temp_files_errors
    : [];

  const parts = [
    `${t("admin.cleanup.result_tokens")}: ${Number(result?.tokens_deleted || 0)}`,
    `${t("admin.cleanup.result_completed")}: ${Number(result?.completed_jobs_deleted || 0)}`,
    `${t("admin.cleanup.result_failed")}: ${Number(result?.failed_jobs_deleted || 0)}`,
    `${t("admin.cleanup.result_cancelled")}: ${Number(result?.cancelled_jobs_deleted || 0)}`,
    `${t("admin.cleanup.result_temp_files")}: ${Number(result?.temp_files_deleted || 0)}`,
  ];

  if (errors.length > 0) {
    parts.push(`${t("admin.cleanup.result_file_errors")}: ${errors.length}`);
  }

  return parts.join(" | ");
}
