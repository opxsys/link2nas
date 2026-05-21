import { request } from "./request.js";
import { normalizeProviderRef, normalizeDestinationRef } from "./normalize.js";

// V2 jobs
export function getJobs(status = "") {
  const query = status ? `?status=${encodeURIComponent(status)}` : "";
  return request(`/api/v2/jobs${query}`, { method: "GET" });
}

export function getJob(jobId) {
  return request(`/api/v2/jobs/${jobId}`, { method: "GET" });
}

export function createJob(payload) {
  return request("/api/v2/jobs", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function createJobsBulk(
  sourceValue,
  autoStart = false,
  sendToDestination = false,
  providerRef = null,
  destinationRef = null
) {
  return request("/api/v2/jobs/bulk", {
    method: "POST",
    body: JSON.stringify({
      source_value: sourceValue,
      auto_start: autoStart,
      send_to_destination: sendToDestination,
      ...normalizeProviderRef(providerRef),
      ...normalizeDestinationRef(destinationRef),
    }),
  });
}

export function createTorrentFileJob(
  file,
  autoStart = false,
  sendToDestination = false,
  providerRef = null,
  destinationRef = null
) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("auto_start", autoStart ? "true" : "false");
  formData.append("send_to_destination", sendToDestination ? "true" : "false");

  const providerPayload = normalizeProviderRef(providerRef);
  if (providerPayload.provider_config_id) {
    formData.append("provider_config_id", providerPayload.provider_config_id);
  } else if (providerPayload.provider_name) {
    formData.append("provider_name", providerPayload.provider_name);
  }

  const destinationPayload = normalizeDestinationRef(destinationRef);
  if (destinationPayload.destination_config_id) {
    formData.append("destination_config_id", destinationPayload.destination_config_id);
  } else if (destinationPayload.destination_name) {
    formData.append("destination_name", destinationPayload.destination_name);
  }

  return request("/api/v2/jobs/torrent-file", {
    method: "POST",
    body: formData,
  });
}

export function startJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/start`, { method: "POST" });
}

export function refreshJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/refresh`, { method: "POST" });
}

export function cancelJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/cancel`, { method: "POST" });
}

export function restartJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/restart`, { method: "POST" });
}

export function deleteJob(jobId) {
  return request(`/api/v2/jobs/${jobId}`, { method: "DELETE" });
}

export function selectJobFiles(jobId, files = "all") {
  return request(`/api/v2/jobs/${jobId}/select-files`, {
    method: "POST",
    body: JSON.stringify({ files }),
  });
}

export function unrestrictJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/unrestrict`, { method: "POST" });
}

export function unrestrictJobFile(jobId, fileId) {
  return request(`/api/v2/jobs/${jobId}/files/${fileId}/unrestrict`, {
    method: "POST",
  });
}

export function sendJobToDestination(jobId, destinationRef = null) {
  return request(`/api/v2/jobs/${jobId}/send-to-destination`, {
    method: "POST",
    body: JSON.stringify({
      ...normalizeDestinationRef(destinationRef),
    }),
  });
}

export function resendJobToDestination(jobId, destinationRef = null) {
  return request(`/api/v2/jobs/${jobId}/resend`, {
    method: "POST",
    body: JSON.stringify({
      ...normalizeDestinationRef(destinationRef),
    }),
  });
}

export function cancelLocalDestinationDownload(jobId) {
  return request(`/api/v2/jobs/${jobId}/destination/cancel`, {
    method: "POST",
  });
}

export function cloneJobWithProvider(
  jobId,
  providerRef,
  destinationRef = null,
  autoStart = true
) {
  return request(`/api/v2/jobs/${jobId}/clone-with-provider`, {
    method: "POST",
    body: JSON.stringify({
      ...normalizeProviderRef(providerRef),
      ...normalizeDestinationRef(destinationRef),
      auto_start: autoStart,
    }),
  });
}

// Compat frontend existant
export function resyncProvider(jobId) {
  return refreshJob(jobId);
}
