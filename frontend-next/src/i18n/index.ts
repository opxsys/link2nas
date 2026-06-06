import { useCallback } from 'react'
import { useMe } from '@/lib/useMe'
import { useStoredLang, setAuthLang, type LangCode } from '@/lib/useAuthLang'
import { en, type TranslationKey } from './en'
import { fr } from './fr'

export type { TranslationKey, LangCode }
export { setAuthLang }

const translations = { en, fr } as const

/** For pre-login / public pages — reads localStorage only, never calls useMe. */
export function useAuthI18n(): {
  lang: LangCode
  setLang: (l: LangCode) => void
  t: (key: TranslationKey) => string
} {
  const lang = useStoredLang()
  const t = useCallback((key: TranslationKey): string => translations[lang][key], [lang])
  return { lang, setLang: setAuthLang, t }
}

/** For app pages (behind ProtectedRoute) — reads me.preferred_language, falls back to stored lang. */
export function useI18n(): { lang: LangCode; t: (key: TranslationKey) => string } {
  const { me } = useMe()
  const storedLang = useStoredLang()
  const lang: LangCode =
    me?.preferred_language === 'en' || me?.preferred_language === 'fr'
      ? me.preferred_language
      : storedLang
  const t = useCallback((key: TranslationKey): string => translations[lang][key], [lang])
  return { lang, t }
}
