export function normalizeProviderRef(providerRef = null) {
  const value = String(providerRef || "").trim();
  if (!value) return {};
  if (["realdebrid", "alldebrid"].includes(value)) {
    return { provider_name: value };
  }
  return { provider_config_id: value };
}

export function normalizeDestinationRef(destinationRef = null) {
  const value = String(destinationRef || "").trim();
  if (!value || value === "links_only") return {};
  if (["synology", "nas", "local"].includes(value)) {
    return { destination_name: value };
  }
  return { destination_config_id: value };
}
