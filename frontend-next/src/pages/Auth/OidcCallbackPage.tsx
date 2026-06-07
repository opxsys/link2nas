import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import AuthShell from './AuthShell'
import { completeOidcLogin, storeToken } from '@/api/auth'
import { invalidateMe } from '@/lib/useMe'
import { useAppInfo } from '@/lib/useAppInfo'
import { useAuthI18n } from '@/i18n'

export default function OidcCallbackPage() {
  const navigate = useNavigate()
  const { appInfo } = useAppInfo()
  const { t } = useAuthI18n()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    completeOidcLogin()
      .then(res => {
        storeToken(res.token)
        invalidateMe()
        navigate(res.user.force_password_change ? '/settings' : '/', { replace: true })
      })
      .catch(() => {
        setError(t('oidcAuthFailed'))
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const appName = appInfo.app_name || 'Link2NAS'

  return (
    <AuthShell appName={appName}>
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
        {error ? (
          <div>
            <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
            <a
              href="/login"
              className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {t('backToLogin')}
            </a>
          </div>
        ) : (
          <div className="flex items-center justify-center gap-3 py-8">
            <Loader2 size={20} className="animate-spin text-muted-foreground" aria-hidden="true" />
            <span className="text-sm text-muted-foreground">{t('oidcCompletingSignIn')}</span>
          </div>
        )}
      </div>
    </AuthShell>
  )
}
