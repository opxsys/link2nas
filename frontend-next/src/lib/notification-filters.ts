type EventShape = { type: string; scope?: string | null }

export function isSystemNotificationEvent(event: EventShape): boolean {
  if (event.scope === 'system') return true
  return event.type.startsWith('system.')
}

export function isUserNotificationEvent(event: EventShape): boolean {
  return !isSystemNotificationEvent(event)
}
