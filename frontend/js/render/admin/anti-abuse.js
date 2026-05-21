import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

export function renderAntiAbuseSection(data) {
  if (!data) {
    return `<p class="muted">${t("admin.security.anti_abuse.loading")}</p>`;
  }

  const backend = html(data.backend || "—");
  const redisConfigured = data.redis_url_configured
    ? t("admin.security.anti_abuse.yes")
    : t("admin.security.anti_abuse.no");
  const counters = Array.isArray(data.counters) ? data.counters : [];

  const rows = counters.map((c) => {
    const status = c.status === "ok"
      ? `<span class="badge badge-ready">${t("admin.security.anti_abuse.status_ok")}</span>`
      : `<span class="badge badge-warning">${t("admin.security.anti_abuse.status_unavailable")}</span>`;

    const hits = c.status === "ok" && c.estimated_hits != null
      ? html(String(c.estimated_hits))
      : "—";
    const identities = c.status === "ok" && c.active_identities != null
      ? html(String(c.active_identities))
      : "—";
    const ttl = c.ttl_seconds != null ? `${html(String(c.ttl_seconds))} s` : "—";

    return `
      <tr>
        <td>${html(c.label || c.kind)}</td>
        <td>${html(String(c.limit))}</td>
        <td>${html(String(c.window_seconds))} s</td>
        <td>${status}</td>
        <td>${hits}</td>
        <td>${identities}</td>
        <td>${ttl}</td>
        <td>
          <button type="button" class="btn btn-sm btn-secondary"
            data-action="reset-anti-abuse-kind" data-kind="${html(c.kind)}">
            ${t("admin.security.anti_abuse.reset_kind")}
          </button>
        </td>
      </tr>
    `;
  }).join("");

  const note = data.note
    ? `<p class="muted" style="margin-top:0.5rem">${html(data.note)}</p>`
    : "";

  return `
    <div class="anti-abuse-meta">
      <span class="muted">${t("admin.security.anti_abuse.backend")} :</span>
      <strong>${backend}</strong>
      &nbsp;·&nbsp;
      <span class="muted">${t("admin.security.anti_abuse.redis_configured")} :</span>
      <strong>${redisConfigured}</strong>
    </div>
    ${note}
    <div class="table-responsive" style="margin-top:0.75rem">
      <table class="admin-table">
        <thead>
          <tr>
            <th>${t("admin.security.anti_abuse.col_counter")}</th>
            <th>${t("admin.security.anti_abuse.col_limit")}</th>
            <th>${t("admin.security.anti_abuse.col_window")}</th>
            <th>${t("admin.security.anti_abuse.col_status")}</th>
            <th>${t("admin.security.anti_abuse.col_hits")}</th>
            <th>${t("admin.security.anti_abuse.col_identities")}</th>
            <th>${t("admin.security.anti_abuse.col_ttl")}</th>
            <th>${t("admin.security.anti_abuse.col_action")}</th>
          </tr>
        </thead>
        <tbody>
          ${rows || `<tr><td colspan="8" class="muted">${t("admin.security.anti_abuse.counters_unavailable")}</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}
