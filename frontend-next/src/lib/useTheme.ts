import { useSyncExternalStore } from 'react'
import {
  type Theme,
  type ThemePreference,
  resolvePreference,
  applyTheme,
  getStoredPreference,
  storePreference,
  toBackendTheme,
  fromBackendTheme,
} from './themes'
import { getMe, updateMe } from '@/api/me'

// ── Module-level store (single instance, no provider needed) ───────────────

const listeners = new Set<() => void>()
let _preference: ThemePreference = getStoredPreference()
let _effective: Theme = resolvePreference(_preference)

function notify(): void { listeners.forEach(cb => cb()) }

// Listen for OS-level dark/light changes when preference is 'auto'
try {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (_preference === 'auto') {
      _effective = resolvePreference('auto')
      applyTheme(_effective)
      notify()
    }
  })
} catch { /* SSR / unsupported */ }

// ── Public write operations ────────────────────────────────────────────────

/** Apply a new preference immediately (DOM + localStorage + backend). */
export function setThemePreference(pref: ThemePreference): void {
  _preference = pref
  _effective = resolvePreference(pref)
  storePreference(pref)
  applyTheme(_effective)
  notify()
  // Fire-and-forget: errors are expected when unauthenticated
  updateMe({ ui_theme: toBackendTheme(pref) }).catch(() => {})
}

/** Reload preference from the backend and reconcile (call once on app mount). */
export async function reloadThemePreference(): Promise<void> {
  try {
    const me = await getMe()
    const pref = fromBackendTheme(me.ui_theme)
    _preference = pref
    _effective = resolvePreference(pref)
    storePreference(pref)
    applyTheme(_effective)
    notify()
  } catch {
    // Unauthenticated or network error — local preference stays in effect
  }
}

// ── Hook ───────────────────────────────────────────────────────────────────

export interface ThemeState {
  /** The stored preference, including 'auto'. */
  preference: ThemePreference
  /** The concrete DOM theme ('auto' resolved to 'light' or 'dark'). */
  effective: Theme
  setPreference: (p: ThemePreference) => void
  reload: () => Promise<void>
}

export function useTheme(): ThemeState {
  const preference = useSyncExternalStore(
    cb => { listeners.add(cb); return () => listeners.delete(cb) },
    () => _preference,
    () => _preference,
  )
  return {
    preference,
    effective: resolvePreference(preference),
    setPreference: setThemePreference,
    reload: reloadThemePreference,
  }
}
