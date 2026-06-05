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

/** Apply preference to DOM + localStorage + notify. No backend sync. */
function applyThemeLocally(pref: ThemePreference): void {
  _preference = pref
  _effective = resolvePreference(pref)
  storePreference(pref)
  applyTheme(_effective)
  notify()
}

/**
 * Apply preference immediately + fire-and-forget backend sync.
 * Errors are silently ignored — suitable for quick switchers (AccountMenu, header).
 */
export function setThemePreference(pref: ThemePreference): void {
  applyThemeLocally(pref)
  updateMe({ ui_theme: toBackendTheme(pref) }).catch(() => {})
}

/**
 * Apply preference immediately + await backend sync.
 * Throws on backend failure — suitable for the Settings page where feedback is shown.
 */
export async function setThemePreferenceAsync(pref: ThemePreference): Promise<void> {
  applyThemeLocally(pref)
  await updateMe({ ui_theme: toBackendTheme(pref) })
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
