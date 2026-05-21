import { request } from "./request.js";
import { normalizeProviderRef } from "./normalize.js";

// V2 providers
export function listProviders() {
  return request("/api/v2/providers", { method: "GET" });
}

export function saveProvider(payload) {
  return request("/api/v2/providers", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteProvider(providerRef) {
  return request(`/api/v2/providers/${encodeURIComponent(providerRef)}`, { method: "DELETE" });
}

export function testDefaultProvider() {
  return request("/api/v2/provider-runtime/me", { method: "GET" });
}

export function testProvider(providerRef) {
  return request(`/api/v2/provider-runtime/test/${encodeURIComponent(providerRef)}`, {
    method: "GET",
  });
}

export function testProviderFromSettings(providerRef = null) {
  return request("/api/v2/settings/provider/test", {
    method: "POST",
    body: JSON.stringify(normalizeProviderRef(providerRef)),
  });
}
