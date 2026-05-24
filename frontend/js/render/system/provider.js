import { formatDate } from "../../utils.js";
import { t } from "../../i18n/index.js";

export function getProviderStatus(system) {
  if (!system || !system.premium || !system.expiration) {
    return {
      dotClass: "rd-dot-neutral",
      tooltip: t("provider.unavailable_or_non_premium"),
    };
  }

  const now = new Date();
  const expiration = new Date(system.expiration);

  if (Number.isNaN(expiration.getTime())) {
    return {
      dotClass: "rd-dot-neutral",
      tooltip: t("provider.unknown_expiration"),
    };
  }

  const diffMs = expiration.getTime() - now.getTime();
  const daysLeft = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

  let dotClass = "rd-dot-success";

  if (daysLeft <= 7) {
    dotClass = "rd-dot-danger";
  } else if (daysLeft <= 15) {
    dotClass = "rd-dot-warning";
  }

  const providerName = system.provider || "provider";

  const tooltip =
    daysLeft <= 0
      ? t("provider.expired_on", {
          provider: providerName,
          date: formatDate(system.expiration),
        })
      : t("provider.expires_on", {
          provider: providerName,
          date: formatDate(system.expiration),
          days: daysLeft,
        });

  return {
    dotClass,
    tooltip,
  };
}

export function formatProviderName(providerName) {
  const value = String(providerName || "").trim().toLowerCase();

  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";

  return "-";
}

export function formatDestination(value) {
  const v = String(value || "").toLowerCase();

  if (v === "synology" || v === "nas") return "NAS Synology";

  if (v === "local") return "Local";

  return "-";
}
