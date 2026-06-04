import { useState } from 'react'
import { Loader2, CheckCircle2, MailX } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { requestPasswordReset } from '@/api/auth'
import { ApiError } from '@/api/client'
import { useAuthLang } from '@/lib/useAuthLang'
import type { AuthView } from './auth.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

interface Props {
  smtpAvailable: boolean
  onSetView: (v: AuthView) => void
}

export default function ForgotPasswordForm({ smtpAvailable, onSetView }: Props) {
  const { t } = useAuthLang()
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!smtpAvailable) {
    return (
      <div>
        <button
          type="button"
          onClick={() => onSetView('login')}
          className="mb-4 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
        >
          ← {t('back')}
        </button>
        <div className="flex items-start gap-3 rounded-md border border-border bg-muted/50 p-4">
          <MailX size={16} className="mt-0.5 shrink-0 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm text-muted-foreground">{t('smtpUnavailable')}</p>
        </div>
      </div>
    )
  }

  if (sent) {
    return (
      <div className="py-2">
        <div className="mb-3 flex items-center gap-2 text-sm font-medium text-foreground">
          <CheckCircle2 size={16} className="text-green-600" aria-hidden="true" />
          {t('sentTitle')}
        </div>
        <p className="mb-6 text-sm text-muted-foreground">{t('resetEmailSent')}</p>
        <button
          type="button"
          onClick={() => onSetView('login')}
          className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
        >
          ← {t('backToLogin')}
        </button>
      </div>
    )
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await requestPasswordReset(email.trim())
      setSent(true)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      <button
        type="button"
        onClick={() => onSetView('login')}
        className="mb-4 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
      >
        ← {t('back')}
      </button>
      <h2 className="mb-6 text-lg font-semibold text-foreground">{t('forgotPassword')}</h2>

      <div className="mb-5">
        <label htmlFor="forgot-email" className={LABEL}>{t('email')}</label>
        <input
          id="forgot-email"
          type="email"
          autoComplete="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          className={INPUT}
          disabled={loading}
        />
      </div>

      {error && (
        <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>
      )}

      <Button type="submit" className="w-full" disabled={loading}>
        {loading && <Loader2 size={14} className="mr-2 animate-spin" aria-hidden="true" />}
        {t('sendResetLink')}
      </Button>
    </form>
  )
}
