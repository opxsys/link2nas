import { useMe } from '@/lib/useMe'
import { en, type TranslationKey } from './en'
import { fr } from './fr'

export type { TranslationKey }
export type LangCode = 'en' | 'fr'

const translations = { en, fr } as const

function detectBrowserLang(): LangCode {
  try {
    return (navigator.language ?? '').startsWith('fr') ? 'fr' : 'en'
  } catch {
    return 'en'
  }
}

function resolveLang(preferred: string | null | undefined): LangCode {
  if (preferred === 'en' || preferred === 'fr') return preferred
  return detectBrowserLang()
}

export function useI18n(): { lang: LangCode; t: (key: TranslationKey) => string } {
  const { me } = useMe()
  const lang = resolveLang(me?.preferred_language)
  const t = (key: TranslationKey): string => translations[lang][key]
  return { lang, t }
}
