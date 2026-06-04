import { useEffect, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import AuthShell from './AuthShell'
import { validatePasswordResetToken, confirmPasswordReset } from '@/api/auth'
import { useAppInfo } from '@/lib/useAppInfo'
import { useAuthLang } from '@/lib/useAuthLang'
import { ApiError } from '@/api/client'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type PageState = 'checking' | 'valid' | 'invalid' | 'done'

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const { appInfo } = useAppInfo()
  const { t } = useAuthLang()
  const rawToken = searchParams.get('token') || ''

  const [pageState, setPageState] = useState<PageState>(() => rawToken ? 'checking' : 'invalid')
  const [password, setPassword] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [fieldError, setFieldError] = useState<string | null>(null)

  // Validate the token on mount — never consumes it
  useEffect(() => {
    if (!rawToken) return
    validatePasswordResetToken(rawToken)
      .then(() => setPageState('valid'))
      .catch(() => setPageState('invalid'))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setFieldError(null)
    if (!password) { setFieldError(`${t('password')} is required`); return }
    if (password !== confirmPw) { setFieldError(t('passwordMismatch')); return }
    setSubmitting(true)
    try {
      await confirmPasswordReset({ token: rawToken, password })
      setPageState('done')
    } catch (err) {
      // Token errors (already used, expired) → show the same invalid card
      const status = err instanceof ApiError ? err.status : 0
      if (status === 400 || status === 401) {
        setPageState('invalid')
      } else {
        setFieldError(err instanceof ApiError ? err.message : t('invalidResetLink'))
      }
    } finally {
      setSubmitting(false)
    }
  }

  const appName = appInfo.app_name || 'Link2NAS'

  return (
    <AuthShell appName={appName}>
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm">

        {pageState === 'checking' && (
          <div className="flex flex-col items-center gap-3 py-6">
            <Loader2 size={24} className="animate-spin text-muted-foreground" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">{t('validatingLink')}</p>
          </div>
        )}

        {pageState === 'invalid' && (
          <div className="flex flex-col items-center gap-4 py-6 text-center">
            <XCircle size={24} className="text-destructive" aria-hidden="true" />
            <p className="text-sm text-destructive">{t('invalidResetLink')}</p>
            <Link
              to="/login"
              className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              ← {t('backToLogin')}
            </Link>
          </div>
        )}

        {pageState === 'done' && (
          <div className="flex flex-col items-center gap-4 py-6 text-center">
            <CheckCircle2 size={24} className="text-green-600" aria-hidden="true" />
            <p className="text-sm text-foreground">{t('passwordResetSuccess')}</p>
            <Link
              to="/login"
              className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {t('goToLogin')}
            </Link>
          </div>
        )}

        {pageState === 'valid' && (
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
                disabled={submitting}
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
                disabled={submitting}
              />
            </div>

            {fieldError && (
              <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {fieldError}
              </p>
            )}

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting && <Loader2 size={14} className="mr-2 animate-spin" aria-hidden="true" />}
              {submitting ? t('resettingPassword') : t('resetPassword')}
            </Button>
          </form>
        )}

      </div>
    </AuthShell>
  )
}
