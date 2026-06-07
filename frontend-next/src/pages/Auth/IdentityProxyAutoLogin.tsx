import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { identityProxyLogin } from '@/api/identity-proxy'
import { useAuthI18n } from '@/i18n'
import type { LoginUser } from '@/api/auth'

interface Props {
  label: string
  onSuccess: (token: string, user: LoginUser) => void
  onFallback: () => void
}

export default function IdentityProxyAutoLogin({ label, onSuccess, onFallback }: Props) {
  const { t } = useAuthI18n()
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    identityProxyLogin()
      .then(res => onSuccess(res.token, res.user))
      .catch(() => {
        setError(t('ipAutoLoginFailed'))
        setLoading(false)
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-3 py-8">
        <Loader2 size={20} className="animate-spin text-muted-foreground" aria-hidden="true" />
        <span className="text-sm text-muted-foreground">
          {label || t('ipAutoLoginSigning')}
        </span>
      </div>
    )
  }

  return (
    <div>
      <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
        {error ?? t('ipAutoLoginFailed')}
      </p>
      <button
        type="button"
        onClick={onFallback}
        className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
      >
        {t('ipFallbackToManual')}
      </button>
    </div>
  )
}
