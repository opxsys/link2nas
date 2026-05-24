import { t } from "../../i18n/index.js";
import { setActivePage } from "../navigation-controller.js";

export function showBatchResultPanel(results) {
  document.getElementById("batch-result-panel")?.remove();

  const okCount = results.filter((r) => r.ok).length;

  const panel = document.createElement("div");
  panel.id = "batch-result-panel";
  panel.className = "batch-result-panel";

  const title = document.createElement("div");
  title.className = "batch-result-title";
  title.textContent = t("batch.result_title");
  panel.appendChild(title);

  const list = document.createElement("ul");
  list.className = "batch-result-list";
  for (const item of results) {
    const li = document.createElement("li");
    li.className = `batch-result-item ${item.ok ? "is-ok" : "is-error"}`;

    const name = document.createElement("span");
    name.className = "batch-result-filename";
    name.textContent = `${item.ok ? "✓" : "✗"} ${item.filename}`;
    li.appendChild(name);

    if (item.ok && item.reused) {
      const note = document.createElement("span");
      note.className = "batch-result-error";
      note.textContent = t("batch.job_reused");
      li.appendChild(note);
    }

    if (!item.ok && item.error) {
      const err = document.createElement("span");
      err.className = "batch-result-error";
      err.textContent = item.error;
      li.appendChild(err);
    }

    list.appendChild(li);
  }
  panel.appendChild(list);

  const actions = document.createElement("div");
  actions.className = "batch-result-actions";

  if (okCount > 0) {
    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.className = "btn btn-primary";
    viewBtn.textContent = t("batch.view_jobs");
    viewBtn.addEventListener("click", () => {
      panel.remove();
      setActivePage("jobs");
    });
    actions.appendChild(viewBtn);
  }

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn";
  closeBtn.textContent = t("batch.close");
  closeBtn.addEventListener("click", () => panel.remove());
  actions.appendChild(closeBtn);

  panel.appendChild(actions);
  const inlineContainer = document.getElementById("create-job-result-panel");
  if (inlineContainer) {
    panel.classList.add("is-inline");
    inlineContainer.innerHTML = "";
    inlineContainer.appendChild(panel);
  } else {
    document.body.appendChild(panel);
  }
}
