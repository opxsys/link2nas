export function formatProviderType(providerType) {
  const value = String(providerType || "").trim().toLowerCase();
  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";
  return providerType || "-";
}

export function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();
  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";
  return destinationType || "-";
}

export function providerOption(config) {
  return {
    value: config.id,
    label: `${config.name || formatProviderType(config.provider_type || config.provider_name)} (${formatProviderType(config.provider_type || config.provider_name)})`,
  };
}

export function destinationOption(config) {
  return {
    value: config.id,
    label: `${config.name || formatDestinationType(config.destination_type || config.destination_name)} (${formatDestinationType(config.destination_type || config.destination_name)})`,
  };
}

export function getActiveDestinationConfigs(job) {
  const configs = Array.isArray(job?.active_real_destination_configs)
    ? job.active_real_destination_configs
    : [];

  // V3 actions must only use real active destination profiles.
  // Do not fallback to active_real_destination_names here, because those are
  // legacy technical names and can recreate fake destinations like "local".
  return configs.filter((config) => config?.id);
}

export function getOtherDestinationConfigs(job) {
  return getActiveDestinationConfigs(job).filter((config) => {
    if (job?.destination_config_id) {
      return config.id !== job.destination_config_id;
    }

    return (config.destination_type || config.destination_name) !== job?.destination_name;
  });
}

export function getOtherProviderConfigs(job) {
  const configs = Array.isArray(job?.active_provider_configs)
    ? job.active_provider_configs
    : [];

  if (configs.length) {
    return configs.filter((config) => config?.id && config.id !== job?.provider_config_id);
  }

  return (job?.active_provider_names || [])
    .filter((providerName) => providerName !== job?.provider_name)
    .map((providerName) => ({
      id: providerName,
      name: providerName,
      provider_type: providerName,
      provider_name: providerName,
    }));
}
