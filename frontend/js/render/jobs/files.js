import { escapeHtml, formatBytes } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { renderAsyncButton } from "./actions.js";
import { isPanelOpen } from "./panel-state.js";

function renderFiles(files, job) {
  if (!files?.length) {
    return `<p class="muted">${t("common.no_file")}</p>`;
  }

  return files.map((file) => {
    const copyFileLabel = file._copyDone ? t("common.copied") : t("common.copy");

    return `
      <div class="file-row">
        <div class="file-main">
          <div class="file-path">
            <strong>${escapeHtml(file.path || file.filename || t("job.file_fallback", { id: file.id }))}</strong>
          </div>
          <div class="muted">
            id=${escapeHtml(file.id)} • ${escapeHtml(formatBytes(file.bytes ?? file.filesize))}
          </div>
          ${file.debrid_link ? `<div class="code-block muted url-truncated">${t("labels.debrid")}: ${escapeHtml(file.debrid_link)}</div>` : ""}
          ${file.download_url ? `<div class="code-block muted url-truncated">${t("labels.direct")}: ${escapeHtml(file.download_url)}</div>` : ""}
        </div>

        <div class="inline-actions">
          ${
            job.output_mode === "per_file" && file.debrid_link
              ? renderAsyncButton({
                  action: "unrestrict-file",
                  jobId: job.id,
                  fileId: file.id,
                  label: file.download_url ? t("job.unlock_again") : t("job.unrestrict"),
                })
              : ""
          }

          ${
            file.download_url
              ? renderAsyncButton({
                  action: "copy-file-url",
                  jobId: job.id,
                  fileId: file.id,
                  label: copyFileLabel,
                })
              : ""
          }
        </div>
      </div>
    `;
  }).join("");
}

export function renderFilesBlock(job) {
  const filesCount = job.files?.length || 0;
  const defaultOpen = filesCount > 0 && filesCount <= 5;
  const filesOpen = isPanelOpen(job, "files", defaultOpen);

  return `
    <details class="detail-block collapsible-block" data-panel="files" ${filesOpen ? "open" : ""}>
      <summary>${t("job.files")} (${filesCount})</summary>
      <div class="collapsible-content">
        ${renderFiles(job.files, job)}
      </div>
    </details>
  `;
}
