import { request } from "./request.js";
import { normalizeDestinationRef } from "./normalize.js";

// V2 destinations
export function listDestinations() {
  return request("/api/v2/destinations", { method: "GET" });
}

export function saveDestination(payload) {
  return request("/api/v2/destinations", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteDestination(destinationRef) {
  return request(`/api/v2/destinations/${encodeURIComponent(destinationRef)}`, { method: "DELETE" });
}

export function testDestination(destinationRef) {
  return request(`/api/v2/destinations/${encodeURIComponent(destinationRef)}/test`, {
    method: "POST",
  });
}

export function testDestinationFromSettings(destinationRef = null) {
  return request("/api/v2/settings/destination/test", {
    method: "POST",
    body: JSON.stringify(normalizeDestinationRef(destinationRef)),
  });
}
