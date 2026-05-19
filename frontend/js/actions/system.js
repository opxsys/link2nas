import { getProviderInfo, getControlCenterInfo, getAdminRuntimeSettings } from "../api.js";
import { state } from "../state.js";
import { renderSystemPanel } from "../render/system.js";

export async function loadSystemInfo() {
  let providerInfo = null;
  let controlCenterInfo = null;
  let runtimeInfo = null;

  try {
    providerInfo = await getProviderInfo();
  } catch (error) {
    providerInfo = {
      username: "-",
      email: "-",
      premium: false,
      type: "error",
      expiration: null,
      points: null,
      locale: null,
      message: error.message,
    };
  }

  try {
    controlCenterInfo = await getControlCenterInfo();
  } catch (error) {
    controlCenterInfo = {
      generated_at: null,
      provider: providerInfo?.provider || null,
      destination_type: null,
      jobs_total: 0,
      jobs_active: 0,
      jobs_with_destination_pending: 0,
      status_counts: {},
      queue: {
        queue_name: "-",
        pending_count: 0,
        started_count: 0,
        failed_count: 0,
        scheduled_count: 0,
        deferred_count: 0,
        workers_total: 0,
        workers_busy: 0,
        workers_idle: 0,
        workers_names: [],
      },
      restart_cooldowns: {
        default: 10,
        realdebrid: 10,
        alldebrid: 10,
      },
      message: error.message,
    };
  }

  if (state.currentUser?.role === "super_admin") {
    try {
      runtimeInfo = await getAdminRuntimeSettings();
    } catch (_) {
      runtimeInfo = null;
    }
  }

  state.system = providerInfo;
  state.controlCenter = controlCenterInfo;
  if (controlCenterInfo?.restart_cooldowns) {
    const cooldowns = controlCenterInfo.restart_cooldowns;

    const hasNewFormat =
      cooldowns.default_seconds !== undefined ||
      cooldowns.realdebrid_seconds !== undefined ||
      cooldowns.alldebrid_seconds !== undefined;

    if (hasNewFormat) {
      state.restartCooldowns = {
        default_seconds:
          cooldowns.default_seconds ??
          state.restartCooldowns?.default_seconds ??
          10,

        realdebrid_seconds:
          cooldowns.realdebrid_seconds ??
          state.restartCooldowns?.realdebrid_seconds ??
          60,

        alldebrid_seconds:
          cooldowns.alldebrid_seconds ??
          state.restartCooldowns?.alldebrid_seconds ??
          8,
      };
    }
  }

  renderSystemPanel(providerInfo, controlCenterInfo, runtimeInfo);
}