import { state } from "../../state.js";

export function getJobPanelState(jobId) {
  const key = String(jobId || "").trim();
  if (!key) return {};

  if (!state.detailPanelsByJobId[key]) {
    state.detailPanelsByJobId[key] = {};
  }

  return state.detailPanelsByJobId[key];
}

export function isPanelOpen(job, panelName, defaultValue = false) {
  const panelState = getJobPanelState(job?.id);
  const value = panelState[panelName];

  return typeof value === "boolean" ? value : defaultValue;
}
