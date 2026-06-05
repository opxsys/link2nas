import { Monitor, Sun, Moon, SunMoon, Eye } from 'lucide-react'
import { cn } from '@/lib/utils'
import { type ThemePreference, THEME_PREFERENCES } from '@/lib/themes'
import { useTheme } from '@/lib/useTheme'
import { useI18n, type TranslationKey } from '@/i18n'

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

export default function ThemeSelector() {
  const { preference, setPreference } = useTheme()
  const { t } = useI18n()

  return (
    <div
      className="flex items-center rounded-md border border-border bg-background p-0.5 gap-0.5"
      role="group"
      aria-label={t('ariaSelectTheme')}
    >
      {THEME_PREFERENCES.map(({ value }) => {
        const Icon = THEME_ICONS[value]
        const active = preference === value
        const label = t(THEME_I18N_KEYS[value])
        return (
          <button
            key={value}
            type="button"
            onClick={() => setPreference(value)}
            className={cn(
              'flex h-7 items-center gap-1.5 rounded px-2 text-xs transition-colors',
              active
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent',
            )}
            aria-label={label}
            aria-pressed={active}
            title={label}
          >
            <Icon size={13} aria-hidden="true" />
            <span className="sr-only xl:not-sr-only">{label}</span>
          </button>
        )
      })}
    </div>
  )
}
