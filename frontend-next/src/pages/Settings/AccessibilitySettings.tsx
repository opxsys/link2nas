import { useState, useRef, useEffect } from 'react'
import { Monitor, Sun, Moon, SunMoon, Eye, CheckCircle2, XCircle, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { cn } from '@/lib/utils'
import { type ThemePreference, THEME_PREFERENCES } from '@/lib/themes'
import { useTheme, setThemePreferenceAsync } from '@/lib/useTheme'
import AccessibilityPreview from './AccessibilityPreview'

const THEME_ICONS: Record<ThemePreference, typeof Sun> = {
  auto:            Monitor,
  light:           Sun,
  dark:            Moon,
  'high-contrast': SunMoon,
  colorblind:      Eye,
}

const THEME_DESCRIPTIONS: Record<ThemePreference, string> = {
  auto:            'Follow the operating system light/dark setting.',
  light:           'Default cool-white interface.',
  dark:            'Reduced brightness for low-light environments.',
  'high-contrast': 'Maximum contrast for readability.',
  colorblind:      'Warm-tinted palette. Orange/amber primary avoids red–green confusion.',
}

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

export default function AccessibilitySettings() {
  const { preference } = useTheme()
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => { if (successTimer.current) clearTimeout(successTimer.current) }, [])

  async function handleThemeClick(value: ThemePreference) {
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      await setThemePreferenceAsync(value)
      setSaveStatus('saved')
      setSaveMessage('Theme saved.')
      if (successTimer.current) clearTimeout(successTimer.current)
      successTimer.current = setTimeout(() => setSaveStatus('idle'), 4000)
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : 'Failed to save theme preference.')
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Theme"
        description="Display preferences saved to your user profile."
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {THEME_PREFERENCES.map(({ value, label }) => {
            const Icon = THEME_ICONS[value]
            const active = preference === value
            return (
              <button
                key={value}
                type="button"
                onClick={() => handleThemeClick(value)}
                disabled={saveStatus === 'saving'}
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
        {saveStatus === 'saved' && (
          <div className="mt-3 flex items-center justify-between gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
            <span className="flex items-center gap-1.5"><CheckCircle2 size={12} aria-hidden="true" />{saveMessage}</span>
            <button onClick={() => setSaveStatus('idle')} className="shrink-0 opacity-60 hover:opacity-100" aria-label="Dismiss">
              <X size={12} aria-hidden="true" />
            </button>
          </div>
        )}
        {saveStatus === 'error' && (
          <div className="mt-3 flex items-center justify-between gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <span className="flex items-center gap-1.5"><XCircle size={12} aria-hidden="true" />{saveMessage}</span>
            <button onClick={() => setSaveStatus('idle')} className="shrink-0 opacity-60 hover:opacity-100" aria-label="Dismiss">
              <X size={12} aria-hidden="true" />
            </button>
          </div>
        )}
        <p className="mt-3 text-xs text-muted-foreground">
          The Account menu in the top-right header provides quick access to the same setting.
        </p>
      </SectionCard>

      <SectionCard
        title="Preview"
        description="How the active theme renders key interface elements."
      >
        <AccessibilityPreview />
      </SectionCard>
    </div>
  )
}
