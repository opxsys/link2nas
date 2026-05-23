import { t } from "../../../i18n/index.js";
import { state } from "../../../state.js";
import { normalizeDestinationName } from "../utils.js";

export function hasRealDestination(job) {
  const value = String(job.destination_type || job.destination_name || "").trim().toLowerCase();
  return value === "synology" || value === "nas" || value === "local";
}

export function getSendDestinationLabel(job) {
  const value = String(job.destination_type || job.destination_name || "").trim().toLowerCase();

  if (value === "synology" || value === "nas") return t("job.send_to_nas");
  if (value === "local") return t("job.send_to_local");

  return t("job.send_to_destination");
}

export function getResendDestinationLabel(job) {
  const value = String(job.destination_type || job.destination_name || "").trim().toLowerCase();

  if (value === "synology" || value === "nas") return t("job.resend_to_nas");
  if (value === "local") return t("job.resend_to_local");

  return t("job.resend_to_destination");
}

export function getOtherProviders(job) {
  const providerConfigs = Array.isArray(job.active_provider_configs)
    ? job.active_provider_configs
    : [];

  if (providerConfigs.length) {
    return providerConfigs.filter((provider) => provider.id !== job.provider_config_id);
  }

  const providers = Array.isArray(job.active_provider_names)
    ? job.active_provider_names
    : [];

  return providers.filter((providerName) => providerName !== job.provider_name);
}

export function getRealDestinations(job) {
  const destinationConfigs = Array.isArray(job.active_real_destination_configs)
    ? job.active_real_destination_configs
    : [];

  // V3 action rendering must only use real active destination profiles.
  // Do not fallback to active_real_destination_names, because legacy technical
  // names can recreate fake destinations like "local" or "synology".
  return destinationConfigs
    .filter((destination) => destination.id)
    .map((destination) => ({
      id: destination.id,
      destination_type: normalizeDestinationName(destination.destination_type || destination.destination_name),
    }))
    .filter((destination) => ["synology", "local"].includes(destination.destination_type));
}

export function canUseOtherDestination(job) {
  const destinations = getRealDestinations(job);
  const currentDestination = job.destination_config_id || normalizeDestinationName(
    job.destination_name || job.destination_type
  );

  if (!destinations.length) {
    return false;
  }

  if (!currentDestination) {
    return destinations.length > 0;
  }

  return destinations.some((destination) => {
    if (typeof destination === "object") {
      return destination.id !== currentDestination;
    }
    return destination !== currentDestination;
  });
}

export function getRestartCooldownSeconds(job) {
  const provider = String(job?.provider_name || "").trim().toLowerCase();
  const cfg = state.restartCooldowns || {};

  if (provider === "realdebrid") {
    return Number(
      cfg.realdebrid_seconds ??
      cfg.realdebrid ??
      cfg.default_seconds ??
      cfg.default ??
      60
    );
  }

  if (provider === "alldebrid") {
    return Number(
      cfg.alldebrid_seconds ??
      cfg.alldebrid ??
      cfg.default_seconds ??
      cfg.default ??
      8
    );
  }

  return Number(
    cfg.default_seconds ??
    cfg.default ??
    10
  );
}

export function getRestartCooldownRemaining(job) {
  const status = String(job?.status || "").trim().toLowerCase();
  if (status !== "cancelled") return 0;

  const cancelledAt = String(job?.cancelled_at || "").trim();
  if (!cancelledAt) return 0;

  const cancelledDate = new Date(cancelledAt);
  if (Number.isNaN(cancelledDate.getTime())) return 0;

  const cooldownSeconds = getRestartCooldownSeconds(job);
  const elapsedSeconds = Math.floor((Date.now() - cancelledDate.getTime()) / 1000);

  return Math.max(0, cooldownSeconds - elapsedSeconds);
}

export function getRestartLabel(job) {
  const remaining = getRestartCooldownRemaining(job);
  if (remaining <= 0) return t("common.restart");
  return `${t("common.restart")} (${remaining}s)`;
}
