/** Lightweight global event channel for announcement data changes. */
const EVENT = 'link2nas:announcements-changed'

/**
 * Notify all subscribers that announcement data may have changed.
 * Call after any create/update/delete/read/acknowledge operation.
 */
export function emitAnnouncementsChanged(): void {
  window.dispatchEvent(new CustomEvent(EVENT))
}

/**
 * Subscribe to announcement data change events.
 * Returns an unsubscribe function suitable for useEffect cleanup.
 */
export function subscribeAnnouncementsChanged(cb: () => void): () => void {
  window.addEventListener(EVENT, cb)
  return () => window.removeEventListener(EVENT, cb)
}
