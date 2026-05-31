import { useState } from 'react'
import { Sun, Moon, SunMoon, Eye } from 'lucide-react'
import { cn } from '@/lib/utils'
import { type Theme, THEMES, getStoredTheme, applyTheme } from '@/lib/themes'

const THEME_ICONS: Record<Theme, typeof Sun> = {
  light: Sun,
  dark: Moon,
  'high-contrast': SunMoon,
  colorblind: Eye,
}

export default function ThemeSelector() {
  const [current, setCurrent] = useState<Theme>(getStoredTheme)

  function handleChange(theme: Theme) {
    applyTheme(theme)
    setCurrent(theme)
  }

  return (
    <div
      className="flex items-center rounded-md border border-border bg-background p-0.5 gap-0.5"
      role="group"
      aria-label="Select theme"
    >
      {THEMES.map(({ value, label }) => {
        const Icon = THEME_ICONS[value]
        const active = current === value
        return (
          <button
            key={value}
            onClick={() => handleChange(value)}
            className={cn(
              'flex h-7 items-center gap-1.5 rounded px-2 text-xs transition-colors',
              active
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent',
            )}
            aria-label={`${label} theme`}
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
