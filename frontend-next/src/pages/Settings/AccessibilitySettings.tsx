import { useState } from 'react'
import { Sun, Moon, SunMoon, Eye } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { cn } from '@/lib/utils'
import { type Theme, THEMES, getStoredTheme, applyTheme } from '@/lib/themes'

const THEME_ICONS: Record<Theme, typeof Sun> = {
  light: Sun,
  dark: Moon,
  'high-contrast': SunMoon,
  colorblind: Eye,
}

const THEME_DESCRIPTIONS: Record<Theme, string> = {
  light: 'Default light interface.',
  dark: 'Reduced brightness for low-light environments.',
  'high-contrast': 'Maximum contrast for readability.',
  colorblind: 'Colorblind-friendly status indicators.',
}

export default function AccessibilitySettings() {
  const [current, setCurrent] = useState<Theme>(getStoredTheme)

  function handleSelect(theme: Theme) {
    applyTheme(theme)
    setCurrent(theme)
  }

  return (
    <SectionCard
      title="Accessibility"
      description="Theme and display preferences. Saved locally in your browser."
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {THEMES.map(({ value, label }) => {
          const Icon = THEME_ICONS[value]
          const active = current === value
          return (
            <button
              key={value}
              type="button"
              onClick={() => handleSelect(value)}
              aria-pressed={active}
              className={cn(
                'flex items-start gap-3 rounded-lg border-2 px-4 py-3 text-left transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                active
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/40 hover:bg-muted/30',
              )}
            >
              <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-muted">
                <Icon
                  size={15}
                  aria-hidden="true"
                  className={active ? 'text-primary' : 'text-foreground'}
                />
              </div>
              <div>
                <p className={cn('text-sm font-medium', active ? 'text-primary' : 'text-foreground')}>
                  {label}
                </p>
                <p className="text-xs text-muted-foreground">{THEME_DESCRIPTIONS[value]}</p>
              </div>
            </button>
          )
        })}
      </div>
    </SectionCard>
  )
}
