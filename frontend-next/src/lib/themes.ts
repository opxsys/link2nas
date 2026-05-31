export type Theme = 'light' | 'dark' | 'high-contrast' | 'colorblind'

export const THEMES: { value: Theme; label: string }[] = [
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
  { value: 'high-contrast', label: 'High Contrast' },
  { value: 'colorblind', label: 'Colorblind' },
]

const STORAGE_KEY = 'link2nas-theme'
const THEME_CLASSES: Theme[] = ['dark', 'high-contrast', 'colorblind']

export function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && THEMES.some((t) => t.value === stored)) {
      return stored as Theme
    }
  } catch {
    // localStorage unavailable
  }
  return 'light'
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement
  root.classList.remove(...THEME_CLASSES)
  if (theme !== 'light') {
    root.classList.add(theme)
  }
  try {
    localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    // localStorage unavailable
  }
}
