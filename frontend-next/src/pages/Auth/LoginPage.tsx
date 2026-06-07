import { useEffect, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import AuthShell from './AuthShell'
import LoginForm from './LoginForm'
import SetupForm from './SetupForm'
import ForgotPasswordForm from './ForgotPasswordForm'
import MagicLoginForm from './MagicLoginForm'
import { getSetupStatus, storeToken, getStoredToken, type SetupStatus } from '@/api/auth'
import { invalidateMe } from '@/lib/useMe'
import { useAppInfo } from '@/lib/useAppInfo'
import { useAuthI18n } from '@/i18n'
import type { LoginUser } from '@/api/auth'
import type { AuthView } from './auth.types'

export default function LoginPage() {
  const navigate = useNavigate()
  const { appInfo } = useAppInfo()
  const { t } = useAuthI18n()
  const [view, setView] = useState<AuthView>('login')
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null)
  const [setupLoading, setSetupLoading] = useState(true)

  const existingToken = getStoredToken()

  useEffect(() => {
    if (existingToken) return
    getSetupStatus()
      .then(s => setSetupStatus(s))
      .catch(() => setSetupStatus({ setup_required: false, single_user_mode: false }))
      .finally(() => setSetupLoading(false))
  }, [existingToken])

  // Redirect away if already authenticated
  if (existingToken) return <Navigate to="/" replace />

  // Single-user mode: no login required — ProtectedRoute handles auth via /me
  if (!setupLoading && setupStatus?.single_user_mode) return <Navigate to="/" replace />

  function handleLoginSuccess(token: string, user: LoginUser) {
    storeToken(token)
    invalidateMe()
    navigate(user.force_password_change ? '/settings' : '/', { replace: true })
  }

  const appName = appInfo.app_name || 'Link2NAS'
  const tagline = appInfo.app_tagline || t('appTaglineFallback')
  const smtpAvailable = appInfo.email_sending_available

  return (
    <AuthShell appName={appName}>
      {tagline && (
        <p className="mb-8 text-center text-sm text-muted-foreground">{tagline}</p>
      )}

      <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
        {setupLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 size={20} className="animate-spin text-muted-foreground" aria-hidden="true" />
          </div>
        ) : setupStatus?.setup_required ? (
          <SetupForm onSuccess={handleLoginSuccess} />
        ) : view === 'forgot-password' ? (
          <ForgotPasswordForm smtpAvailable={smtpAvailable} onSetView={setView} />
        ) : view === 'magic-login' ? (
          <MagicLoginForm smtpAvailable={smtpAvailable} onSetView={setView} />
        ) : (
          <LoginForm
            emailAvailable={smtpAvailable}
            onSuccess={handleLoginSuccess}
            onSetView={setView}
          />
        )}
      </div>
    </AuthShell>
  )
}
