import { escapeHtml, formatBytes, formatDate, formatJobStatus } from "../../utils.js";
import { t } from "../../i18n/index.js";

function getDisplaySourceType(job) {
  if (job.source_type === "magnet" || job.source_type === "torrent_file") return t("jobs.torrent");
  if (job.source_type === "direct_link") return t("jobs.direct");
  return job.source_type || t("common.none");
}

function formatProviderType(providerType) {
  const value = String(providerType || "").trim().toLowerCase();
  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";
  return t("common.none");
}

export function formatProviderProfile(job) {
  const name = String(job.provider_profile_name || "").trim();
  const type = formatProviderType(job.provider_type || job.provider_name);
  return name ? `${name} (${type})` : type;
}

function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();
  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";
  return t("common.none");
}

export function formatDestinationProfile(job) {
  const name = String(job.destination_profile_name || "").trim();
  const type = formatDestinationType(job.destination_type || job.destination_name);
  return name ? `${name} (${type})` : type;
}

export function renderSummaryBlock(job, progress) {
  return `
    <div class="detail-block detail-block-first">
      <h3>${t("job.summary")}</h3>
      <div class="kv-grid">
        <div class="kv-item"><strong>${t("job.source")}</strong><div>${escapeHtml(getDisplaySourceType(job))}</div></div>
        <div class="kv-item"><strong>${t("common.status")}</strong><div>${escapeHtml(formatJobStatus(job.status))}</div></div>
        <div class="kv-item"><strong>Provider</strong><div>${escapeHtml(formatProviderProfile(job))}</div></div>
        <div class="kv-item"><strong>Destination</strong><div>${escapeHtml(formatDestinationProfile(job))}</div></div>
        <div class="kv-item kv-item-wide">
          <strong>${t("job.progress")}</strong>
          <div>${escapeHtml(String(progress))}%</div>
          <div class="progress summary-progress"><span style="width:${Number(progress)}%"></span></div>
        </div>
        <div class="kv-item"><strong>${t("job.size")}</strong><div>${escapeHtml(formatBytes(job.filesize))}</div></div>
        <div class="kv-item"><strong>${t("job.created_at")}</strong><div>${escapeHtml(formatDate(job.created_at))}</div></div>
        <div class="kv-item"><strong>${t("job.updated_at")}</strong><div>${escapeHtml(formatDate(job.updated_at))}</div></div>
      </div>
    </div>
  `;
}
