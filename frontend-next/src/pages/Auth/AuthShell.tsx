import { type ReactNode, useState, useRef, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Monitor, Sun, Moon, SunMoon, Eye, Settings2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { type ThemePreference, THEME_PREFERENCES } from '@/lib/themes'
import { useTheme } from '@/lib/useTheme'
import { useAuthI18n, type TranslationKey } from '@/i18n'

const THEME_ICONS: Record<ThemePreference, typeof Sun> = {
  auto:            Monitor,
  light:           Sun,
  dark:            Moon,
  'high-contrast': SunMoon,
  colorblind:      Eye,
}

const THEME_I18N_KEYS: Record<ThemePreference, TranslationKey> = {
  auto:            'themeAuto',
  light:           'themeLight',
  dark:            'themeDark',
  'high-contrast': 'themeHighContrast',
  colorblind:      'themeColorblind',
}

function AuthSettingsMenu() {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const { preference, setPreference } = useTheme()
  const { lang, setLang, t } = useAuthI18n()

  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') setOpen(false) }
    function onMouse(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onMouse)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onMouse)
    }
  }, [open])

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={t('ariaAuthSettings')}
        className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Settings2 size={16} aria-hidden="true" />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-50 mt-1 w-56 overflow-hidden rounded-lg border border-border bg-card shadow-lg"
        >
          <div className="border-b border-border px-3 py-2.5">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {t('appearance')}
            </p>
            <div className="flex flex-wrap gap-1">
              {THEME_PREFERENCES.map(({ value }) => {
                const Icon = THEME_ICONS[value]
                const active = preference === value
                const label = t(THEME_I18N_KEYS[value])
                return (
                  <button
                    key={value}
                    onClick={() => setPreference(value)}
                    aria-pressed={active}
                    title={label}
                    className={cn(
                      'flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors',
                      active
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                    )}
                  >
                    <Icon size={12} aria-hidden="true" />
                    {label}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="px-3 py-2.5">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {t('language')}
            </p>
            <div className="flex gap-1">
              {(['fr', 'en'] as const).map((code) => (
                <button
                  key={code}
                  onClick={() => setLang(code)}
                  aria-pressed={lang === code}
                  className={cn(
                    'rounded px-3 py-1 text-xs font-medium transition-colors',
                    lang === code
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                  )}
                >
                  {code === 'fr' ? 'FR' : 'EN'}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

interface AuthShellProps {
  appName: string
  children: ReactNode
}

export default function AuthShell({ appName, children }: AuthShellProps) {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-card px-4">
        <Link
          to="/login"
          className="text-sm font-semibold text-foreground transition-colors hover:text-primary"
        >
          {appName}
        </Link>
        <AuthSettingsMenu />
      </header>

      <main className="flex flex-1 items-start justify-center px-4 py-12 sm:items-center">
        <div className="w-full max-w-sm">
          {children}
        </div>
      </main>
    </div>
  )
}
