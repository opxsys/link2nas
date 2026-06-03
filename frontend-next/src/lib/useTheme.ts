import { useSyncExternalStore } from 'react'
import { type Theme, getStoredTheme, applyTheme } from './themes'

// Module-level store — one instance for the whole app, no provider needed.
const listeners = new Set<() => void>()
let _current: Theme = getStoredTheme()

function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  return () => listeners.delete(cb)
}

function getSnapshot(): Theme {
  return _current
}

export function setTheme(theme: Theme): void {
  applyTheme(theme)
  _current = theme
  listeners.forEach((cb) => cb())
}

export function useTheme(): [Theme, (theme: Theme) => void] {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
  return [theme, setTheme]
}
