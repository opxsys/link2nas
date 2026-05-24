import { bindJobSelectionEvents } from "./selection-events.js";
import { bindJobActionEvents } from "./action-events.js";
import { bindCreateJobEvents } from "./create-job-events.js";

export function bindJobsEvents() {
  bindJobSelectionEvents();
  bindJobActionEvents();
  bindCreateJobEvents();
}
