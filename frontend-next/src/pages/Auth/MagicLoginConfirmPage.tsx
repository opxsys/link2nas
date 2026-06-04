import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'
import AuthShell from './AuthShell'
import { confirmMagicLogin, storeToken } from '@/api/auth'
import { invalidateMe } from '@/lib/useMe'
import { useAppInfo } from '@/lib/useAppInfo'
import { useAuthLang } from '@/lib/useAuthLang'
import { ApiError } from '@/api/client'

export default function MagicLoginConfirmPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { appInfo } = useAppInfo()
  const { t } = useAuthLang()
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  useEffect(() => {
    const rawToken = searchParams.get('token') || ''
    if (!rawToken) {
      setStatus('error')
      setErrorMsg(t('invalidToken'))
      return
    }
    confirmMagicLogin(rawToken)
      .then(res => {
        storeToken(res.token)
        invalidateMe()
        setStatus('success')
        setTimeout(() => navigate('/', { replace: true }), 1200)
      })
      .catch(err => {
        setStatus('error')
        setErrorMsg(err instanceof ApiError ? err.message : t('invalidToken'))
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const appName = appInfo.app_name || 'Link2NAS'

  return (
    <AuthShell appName={appName}>
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
        {status === 'loading' && (
          <div className="flex flex-col items-center gap-3 py-6">
            <Loader2 size={24} className="animate-spin text-muted-foreground" aria-hidden="true" />
            <p className="text-sm text-muted-foreground">{t('confirmingLogin')}</p>
          </div>
        )}

        {status === 'success' && (
          <div className="flex flex-col items-center gap-3 py-6">
            <CheckCircle2 size={24} className="text-green-600" aria-hidden="true" />
            <p className="text-sm text-foreground">{t('loginSuccess')}</p>
          </div>
        )}

        {status === 'error' && (
          <div className="flex flex-col items-center gap-4 py-6 text-center">
            <XCircle size={24} className="text-destructive" aria-hidden="true" />
            <p className="text-sm text-destructive">{errorMsg}</p>
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
