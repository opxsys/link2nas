import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { login } from '@/api/auth'
import { ApiError } from '@/api/client'
import { useAuthI18n } from '@/i18n'
import type { LoginUser } from '@/api/auth'
import type { OidcPublicProvider } from '@/api/app-info'
import type { AuthView } from './auth.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

interface Props {
  emailAvailable: boolean
  onSuccess: (token: string, user: LoginUser) => void
  onSetView: (v: AuthView) => void
  oidcProviders?: OidcPublicProvider[]
}

export default function LoginForm({ emailAvailable, onSuccess, onSetView, oidcProviders }: Props) {
  const { t } = useAuthI18n()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const providers = oidcProviders ?? []
  const hasOidc = providers.length > 0

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
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
      <h2 className="mb-1 text-lg font-semibold text-foreground">{t('loginTitle')}</h2>
      <p className="mb-6 text-sm text-muted-foreground">{t('loginSubtitle')}</p>

      <div className="mb-4">
        <label htmlFor="login-email" className={LABEL}>{t('email')}</label>
        <input
          id="login-email"
          type="email"
          autoComplete="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          className={INPUT}
          disabled={loading}
        />
      </div>

      <div className="mb-5">
        <label htmlFor="login-password" className={LABEL}>{t('password')}</label>
        <input
          id="login-password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={e => setPassword(e.target.value)}
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
        {t('signIn')}
      </Button>

      {emailAvailable && (
        <div className="mt-4 flex flex-col gap-2">
          <button
            type="button"
            onClick={() => onSetView('forgot-password')}
            className="text-center text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
          >
            {t('forgotPassword')}
          </button>
          <button
            type="button"
            onClick={() => onSetView('magic-login')}
            className="text-center text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
          >
            {t('magicLogin')}
          </button>
        </div>
      )}

      {hasOidc && (
        <>
          <div className="relative my-5 flex items-center">
            <div className="flex-1 border-t border-border" />
            <span className="mx-3 text-xs text-muted-foreground">{t('oidcOr')}</span>
            <div className="flex-1 border-t border-border" />
          </div>
          <div className="flex flex-col gap-2">
            {providers.map((provider) => (
              <Button
                key={provider.slug}
                type="button"
                variant="outline"
                className="w-full"
                onClick={() => { window.location.href = `/api/v2/auth/oidc/${provider.slug}/initiate` }}
              >
                {provider.button_label || t('oidcSsoFallback')}
              </Button>
            ))}
          </div>
        </>
      )}
    </form>
  )
}
