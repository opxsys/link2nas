import { useMe } from '@/lib/useMe'
import { useStoredLang, setAuthLang, type LangCode } from '@/lib/useAuthLang'
import { en, type TranslationKey } from './en'
import { fr } from './fr'

export type { TranslationKey, LangCode }
export { setAuthLang }

const translations = { en, fr } as const

function makeT(lang: LangCode): (key: TranslationKey) => string {
  return (key: TranslationKey) => translations[lang][key]
}

/** For pre-login / public pages — reads localStorage only, never calls useMe. */
export function useAuthI18n(): {
  lang: LangCode
  setLang: (l: LangCode) => void
  t: (key: TranslationKey) => string
} {
  const lang = useStoredLang()
  return { lang, setLang: setAuthLang, t: makeT(lang) }
}

/** For app pages (behind ProtectedRoute) — reads me.preferred_language, falls back to stored lang. */
export function useI18n(): { lang: LangCode; t: (key: TranslationKey) => string } {
  const { me } = useMe()
  const storedLang = useStoredLang()
  const lang: LangCode =
    me?.preferred_language === 'en' || me?.preferred_language === 'fr'
      ? me.preferred_language
      : storedLang
  return { lang, t: makeT(lang) }
}
