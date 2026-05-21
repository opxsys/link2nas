import { API_BASE } from "../config.js";
import { getToken } from "../core/session.js";

export class ApiError extends Error {
  constructor(message, status = 0, data = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

export async function request(path, options = {}) {
  const isFormData = options.body instanceof FormData;
  const token = getToken();

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(isFormData ? {} : { "Content-Type": "application/json" }),
      ...(token ? { "X-Api-Key": token } : {}),
      ...(options.headers || {}),
    },
  });

  if (response.status === 204) return null;

  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();

  let data = null;
  if (text) {
    if (contentType.includes("application/json")) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { message: text };
      }
    } else {
      data = { message: text };
    }
  }

  if (!response.ok) {
    let message = data?.error || data?.message || `HTTP ${response.status}`;

    if (typeof message === "string" && message.trim().startsWith("<")) {
      message = `Erreur serveur HTTP ${response.status}`;
    }

    throw new ApiError(message, response.status, data);
  }

  return data;
}
