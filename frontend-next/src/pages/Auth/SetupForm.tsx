import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { createFirstAdmin, login } from '@/api/auth'
import { ApiError } from '@/api/client'
import { useAuthLang } from '@/lib/useAuthLang'
import type { LoginUser } from '@/api/auth'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

interface Props {
  onSuccess: (token: string, user: LoginUser) => void
}

export default function SetupForm({ onSuccess }: Props) {
  const { t, lang, setLang } = useAuthLang()
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (!email.trim()) { setError(t('emailRequired')); return }
    if (!password) { setError(t('passwordRequired')); return }
    if (password !== confirmPw) { setError(t('passwordMismatch')); return }
    setLoading(true)
    try {
      await createFirstAdmin({
        email: email.trim(),
        password,
        display_name: displayName.trim() || null,
        preferred_language: lang,
      })
      const res = await login(email.trim(), password)
      onSuccess(res.token, res.user)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      <h2 className="mb-1 text-lg font-semibold text-foreground">{t('setupTitle')}</h2>
      <p className="mb-6 text-sm text-muted-foreground">{t('setupSubtitle')}</p>

      <div className="mb-4">
        <label htmlFor="setup-name" className={LABEL}>{t('displayName')}</label>
        <input id="setup-name" type="text" autoComplete="name"
          value={displayName} onChange={e => setDisplayName(e.target.value)}
          className={INPUT} disabled={loading} />
      </div>

      <div className="mb-4">
        <label htmlFor="setup-email" className={LABEL}>{t('email')}</label>
        <input id="setup-email" type="email" autoComplete="email"
          value={email} onChange={e => setEmail(e.target.value)}
          className={INPUT} disabled={loading} />
      </div>

      <div className="mb-4">
        <label htmlFor="setup-pw" className={LABEL}>{t('password')}</label>
        <input id="setup-pw" type="password" autoComplete="new-password"
          value={password} onChange={e => setPassword(e.target.value)}
          className={INPUT} disabled={loading} />
      </div>

      <div className="mb-4">
        <label htmlFor="setup-confirm-pw" className={LABEL}>{t('confirmPassword')}</label>
        <input id="setup-confirm-pw" type="password" autoComplete="new-password"
          value={confirmPw} onChange={e => setConfirmPw(e.target.value)}
          className={INPUT} disabled={loading} />
      </div>

      <div className="mb-5">
        <label className={LABEL}>{t('language')}</label>
        <div className="flex gap-2">
          {(['fr', 'en'] as const).map(code => (
            <button
              key={code}
              type="button"
              onClick={() => setLang(code)}
              aria-pressed={lang === code}
              className={cn(
                'rounded-md border px-3 py-1.5 text-sm transition-colors',
                lang === code
                  ? 'border-primary bg-primary text-primary-foreground'
                  : 'border-border text-muted-foreground hover:bg-accent hover:text-foreground',
              )}
            >
              {code === 'fr' ? 'Français' : 'English'}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      <Button type="submit" className="w-full" disabled={loading}>
        {loading && <Loader2 size={14} className="mr-2 animate-spin" aria-hidden="true" />}
        {loading ? t('creatingAdmin') : t('createAdmin')}
      </Button>
    </form>
  )
}
