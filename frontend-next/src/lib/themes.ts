/** What the user selects — includes 'auto' for system default. */
export type ThemePreference = 'auto' | 'light' | 'dark' | 'high-contrast' | 'colorblind'

/** What is actually applied to the DOM — 'auto' is never a DOM class. */
export type Theme = 'light' | 'dark' | 'high-contrast' | 'colorblind'

export const THEME_PREFERENCES: { value: ThemePreference; label: string }[] = [
  { value: 'auto',          label: 'Auto'         },
  { value: 'light',         label: 'Light'        },
  { value: 'dark',          label: 'Dark'         },
  { value: 'high-contrast', label: 'High Contrast'},
  { value: 'colorblind',    label: 'Colorblind'   },
]

const STORAGE_KEY = 'link2nas-theme'
const APPLIED_CLASSES: Theme[] = ['dark', 'high-contrast', 'colorblind']

function systemPrefersDark(): boolean {
  try { return window.matchMedia('(prefers-color-scheme: dark)').matches } catch { return false }
}

/** Resolve a preference (possibly 'auto') to a concrete DOM theme. */
export function resolvePreference(pref: ThemePreference): Theme {
  if (pref === 'auto') return systemPrefersDark() ? 'dark' : 'light'
  return pref
}

/** Apply a concrete theme to the document. */
export function applyTheme(theme: Theme): void {
  const root = document.documentElement
  root.classList.remove(...APPLIED_CLASSES)
  if (theme !== 'light') root.classList.add(theme)
}

/** Read stored preference from localStorage (fast, synchronous). */
export function getStoredPreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v && THEME_PREFERENCES.some(t => t.value === v)) return v as ThemePreference
  } catch { /* ignore */ }
  return 'auto'
}

/** Write preference to localStorage (fast cache / fallback). */
export function storePreference(pref: ThemePreference): void {
  try { localStorage.setItem(STORAGE_KEY, pref) } catch { /* ignore */ }
}

/** Apply the stored preference immediately — call before React mounts to prevent flash. */
export function applyStoredTheme(): void {
  applyTheme(resolvePreference(getStoredPreference()))
}

// ── Backend value mapping ──────────────────────────────────────────────────
// Backend valid values: "auto" | "light" | "night" | "high_contrast" | "colorblind"

export function toBackendTheme(pref: ThemePreference): string {
  if (pref === 'dark') return 'night'
  if (pref === 'high-contrast') return 'high_contrast'
  return pref
}

export function fromBackendTheme(val: string): ThemePreference {
  if (val === 'night') return 'dark'
  if (val === 'high_contrast') return 'high-contrast'
  const known: ThemePreference[] = ['auto', 'light', 'colorblind']
  return known.includes(val as ThemePreference) ? (val as ThemePreference) : 'auto'
}
