import { useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import AuthShell from './AuthShell'
import { confirmPasswordReset } from '@/api/auth'
import { useAppInfo } from '@/lib/useAppInfo'
import { useAuthLang } from '@/lib/useAuthLang'
import { ApiError } from '@/api/client'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const { appInfo } = useAppInfo()
  const { t } = useAuthLang()
  const rawToken = searchParams.get('token') || ''

  const [password, setPassword] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const appName = appInfo.app_name || 'Link2NAS'

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (!password) { setError(`${t('password')} is required`); return }
    if (password !== confirmPw) { setError(t('passwordMismatch')); return }
    setLoading(true)
    try {
      await confirmPasswordReset({ token: rawToken, password })
      setDone(true)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('invalidToken'))
    } finally {
      setLoading(false)
    }
  }

  if (!rawToken) {
    return (
      <AuthShell appName={appName}>
        <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <div className="flex flex-col items-center gap-4 py-6 text-center">
            <XCircle size={24} className="text-destructive" aria-hidden="true" />
            <p className="text-sm text-destructive">{t('invalidToken')}</p>
            <Link to="/login" className="text-sm text-muted-foreground hover:underline">
              ← {t('backToLogin')}
            </Link>
          </div>
        </div>
      </AuthShell>
    )
  }

  if (done) {
    return (
      <AuthShell appName={appName}>
        <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <div className="flex flex-col items-center gap-4 py-6 text-center">
            <CheckCircle2 size={24} className="text-green-600" aria-hidden="true" />
            <p className="text-sm text-foreground">{t('passwordResetSuccess')}</p>
            <Link to="/login" className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">
              {t('goToLogin')}
            </Link>
          </div>
        </div>
      </AuthShell>
    )
  }

  return (
    <AuthShell appName={appName}>
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
        <form onSubmit={handleSubmit} noValidate>
          <h2 className="mb-6 text-lg font-semibold text-foreground">{t('resetPassword')}</h2>

          <div className="mb-4">
            <label htmlFor="reset-pw" className={LABEL}>{t('newPassword')}</label>
            <input
              id="reset-pw"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              className={INPUT}
              disabled={loading}
            />
          </div>

          <div className="mb-5">
            <label htmlFor="reset-confirm-pw" className={LABEL}>{t('confirmNewPassword')}</label>
            <input
              id="reset-confirm-pw"
              type="password"
              autoComplete="new-password"
              value={confirmPw}
              onChange={e => setConfirmPw(e.target.value)}
              className={INPUT}
              disabled={loading}
            />
          </div>

          {error && (
            <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 size={14} className="mr-2 animate-spin" aria-hidden="true" />}
            {loading ? t('resettingPassword') : t('resetPassword')}
          </Button>
        </form>
      </div>
    </AuthShell>
  )
}
