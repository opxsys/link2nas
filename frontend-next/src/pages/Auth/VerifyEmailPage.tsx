import { useEffect, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'
import AuthShell from './AuthShell'
import { getTokenStatus, confirmEmailVerification } from '@/api/auth'
import { useAppInfo } from '@/lib/useAppInfo'
import { useAuthLang } from '@/lib/useAuthLang'

type Status = 'loading' | 'success' | 'error'

export default function VerifyEmailPage() {
  const [searchParams] = useSearchParams()
  const { appInfo } = useAppInfo()
  const { t } = useAuthLang()
  const rawToken = searchParams.get('token') || ''
  const [status, setStatus] = useState<Status>('loading')

  useEffect(() => {
    if (!rawToken) { setStatus('error'); return }
    setStatus('loading')
    getTokenStatus(rawToken)
      .then((s) => {
        if (!s.valid || s.token_type !== 'email_verification') {
          setStatus('error')
          return
        }
        return confirmEmailVerification(rawToken)
      })
      .then((res) => { if (res !== undefined) setStatus('success') })
      .catch(() => setStatus('error'))
  }, [rawToken])

  const appName = appInfo.app_name || 'Link2NAS'

  return (
    <AuthShell appName={appName}>
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm">

        {status === 'loading' && (
          <div className="flex flex-col items-center gap-3 py-6">
            <Loader2 size={24} className="animate-spin text-muted-foreground" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">{t('verifyingEmail')}</p>
          </div>
        )}

        {status === 'success' && (
          <div className="flex flex-col items-center gap-4 py-6 text-center">
            <CheckCircle2 size={24} className="text-green-600" aria-hidden="true" />
            <p className="text-sm text-foreground">{t('emailVerified')}</p>
            <Link
              to="/login"
              className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {t('goToLogin')}
            </Link>
          </div>
        )}

        {status === 'error' && (
          <div className="flex flex-col items-center gap-4 py-6 text-center">
            <XCircle size={24} className="text-destructive" aria-hidden="true" />
            <p className="text-sm text-destructive">{t('invalidVerifyLink')}</p>
            <Link
              to="/login"
              className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              ← {t('backToLogin')}
            </Link>
          </div>
        )}

      </div>
    </AuthShell>
  )
}
