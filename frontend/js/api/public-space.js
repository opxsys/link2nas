import { request } from "./request.js";

// User public space
export function getMyPublicSpace() {
  return request("/api/v2/me/public-space", { method: "GET" });
}

export function cleanMyPublicSpace() {
  return request("/api/v2/me/public-space/cleanup", { method: "POST" });
}
