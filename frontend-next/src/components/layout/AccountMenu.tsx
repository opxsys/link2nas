import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { User, LogOut, ChevronDown, Monitor, Sun, Moon, SunMoon, Eye } from 'lucide-react'
import { cn } from '@/lib/utils'
import { type ThemePreference, THEME_PREFERENCES } from '@/lib/themes'
import { useTheme } from '@/lib/useTheme'
import { updateMe } from '@/api/me'
import { useMe, invalidateMe } from '@/lib/useMe'

const THEME_ICONS: Record<ThemePreference, typeof Sun> = {
  auto:            Monitor,
  light:           Sun,
  dark:            Moon,
  'high-contrast': SunMoon,
  colorblind:      Eye,
}

const LANGUAGES = [
  { value: '',   label: 'System' },
  { value: 'en', label: 'English' },
  { value: 'fr', label: 'Français' },
]

export default function AccountMenu() {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const { preference, setPreference } = useTheme()
  const { me } = useMe()
  const [lang, setLang] = useState(me?.preferred_language ?? '')

  useEffect(() => {
    if (me) setLang(me.preferred_language ?? '')
  }, [me])

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

  async function handleLangChange(value: string) {
    setLang(value)
    try {
      await updateMe({ preferred_language: value || null })
      invalidateMe()
    } catch { /* ignore */ }
  }

  function handleLogout() {
    localStorage.removeItem('link2nas_token')
    window.location.href = '/'
  }

  const initials = me ? (me.display_name || me.email).charAt(0).toUpperCase() : 'U'
  const username  = me?.display_name || me?.email || 'Account'

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[11px] font-semibold text-primary select-none">
          {initials}
        </div>
        <span className="hidden max-w-[120px] truncate sm:inline">{username}</span>
        <ChevronDown size={13} aria-hidden="true" className={cn('transition-transform duration-150', open && 'rotate-180')} />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-50 mt-1 w-64 overflow-hidden rounded-lg border border-border bg-card shadow-lg"
        >
          {/* My Account */}
          <div className="p-1">
            <button
              role="menuitem"
              className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-foreground transition-colors hover:bg-accent"
              onClick={() => { setOpen(false); navigate('/settings') }}
            >
              <User size={14} aria-hidden="true" />
              My Account
            </button>
          </div>

          {/* Appearance */}
          <div className="border-t border-border px-3 py-2.5">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Appearance
            </p>
            <div className="flex flex-wrap gap-1">
              {THEME_PREFERENCES.map(({ value, label }) => {
                const Icon = THEME_ICONS[value]
                const active = preference === value
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

          {/* Language */}
          <div className="border-t border-border px-3 py-2.5">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Language
            </p>
            <div className="flex gap-1">
              {LANGUAGES.map(({ value, label }) => (
                <button
                  key={value}
                  onClick={() => handleLangChange(value)}
                  aria-pressed={lang === value}
                  className={cn(
                    'rounded px-2 py-1 text-xs transition-colors',
                    lang === value
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Sign out */}
          <div className="border-t border-border p-1">
            <button
              role="menuitem"
              className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-destructive transition-colors hover:bg-destructive/10"
              onClick={handleLogout}
            >
              <LogOut size={14} aria-hidden="true" />
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
