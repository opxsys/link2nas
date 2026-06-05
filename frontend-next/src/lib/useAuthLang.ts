import { useSyncExternalStore } from 'react'

export type LangCode = 'en' | 'fr'

const STORAGE_KEY = 'link2nas-lang'
const listeners = new Set<() => void>()

function getInitialLang(): LangCode {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'en' || v === 'fr') return v
  } catch { /* ignore */ }
  try {
    return (navigator.language ?? '').startsWith('fr') ? 'fr' : 'en'
  } catch {
    return 'fr'
  }
}

let _lang: LangCode = getInitialLang()

function notify(): void {
  listeners.forEach(cb => cb())
}

export function setAuthLang(l: LangCode): void {
  _lang = l
  try { localStorage.setItem(STORAGE_KEY, l) } catch { /* ignore */ }
  notify()
}

export function useStoredLang(): LangCode {
  return useSyncExternalStore(
    cb => { listeners.add(cb); return () => listeners.delete(cb) },
    () => _lang,
    () => _lang,
  )
}
