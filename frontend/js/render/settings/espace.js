import { t } from "../../i18n/index.js";
import { html, formatBytes } from "./utils.js";

export function renderEspaceContent(data) {
  const files = Array.isArray(data?.files) ? data.files : [];
  const url = data?.url || "";
  const fileCount = data?.file_count ?? 0;
  const totalSize = data?.total_size_bytes ?? 0;

  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.espace.title")}</h2>
        <p class="muted">${t("settings.espace.subtitle")}</p>
      </div>
    </div>

    <article class="job-card">
      <div style="display:flex;flex-direction:column;gap:8px;">
        <label style="font-size:0.875rem;color:var(--text-muted)">${t("settings.espace.public_url_label")}</label>
        <div style="display:flex;gap:8px;align-items:center;">
          <a class="public-space-url" href="${html(url)}" target="_blank" rel="noopener" title="${html(url)}">${html(url)}</a>
          <button class="btn btn-sm public-space-copy-btn" id="espace-copy-btn" data-url="${html(url)}" type="button" title="${t("settings.espace.copy_link")}" aria-label="${t("settings.espace.copy_link")}">&#x29C9;</button>
        </div>
      </div>

      <div style="display:flex;gap:24px;margin-top:16px;">
        <div>
          <div class="muted" style="font-size:0.75rem;">${t("settings.espace.file_count")}</div>
          <div style="font-weight:600;">${fileCount}</div>
        </div>
        <div>
          <div class="muted" style="font-size:0.75rem;">${t("settings.espace.total_size")}</div>
          <div style="font-weight:600;">${formatBytes(totalSize)}</div>
        </div>
      </div>
    </article>

    <div class="section-header" style="margin-top:8px;">
      <h3 style="font-size:1rem;">${t("settings.espace.files_title")}</h3>
    </div>

    ${
      files.length === 0
        ? `<p class="muted">${t("settings.espace.no_files")}</p>`
        : `<div class="settings-list">${files.map((f) => {
            const encodedPath = f.relative_path.split("/").map(encodeURIComponent).join("/");
            const fileUrl = `${url.replace(/\/$/, "")}/files/${encodedPath}`;
            return `
            <article class="job-card" style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
              <a href="${html(fileUrl)}" target="_blank" rel="noopener" style="word-break:break-all;color:var(--accent);">${html(f.relative_path)}</a>
              <span class="muted" style="white-space:nowrap;font-size:0.8rem;">${formatBytes(f.size_bytes)}</span>
            </article>`;
          }).join("")}</div>`
    }

    <div id="espace-feedback" style="margin-top:8px;" hidden></div>

    <button class="btn" id="espace-cleanup-btn" style="margin-top:8px;color:var(--color-danger,#f87171);">
      ${t("settings.espace.cleanup_btn")}
    </button>
  `;
}

export function renderEspacePanel() {
  return `
    <div id="espace-content">
      <p class="muted">${t("settings.espace.loading")}</p>
    </div>
  `;
}
