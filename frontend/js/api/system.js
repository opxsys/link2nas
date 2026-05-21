import { request } from "./request.js";

export function getProviderInfo() {
  return request("/api/v2/system/provider", { method: "GET" });
}

export function getControlCenterInfo() {
  return request("/api/v2/system/control-center", { method: "GET" });
}
