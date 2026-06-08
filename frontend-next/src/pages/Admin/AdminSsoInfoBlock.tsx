import { useState, useEffect } from 'react'
import { Info, Copy, CheckCircle2 } from 'lucide-react'
import { getGeneralSettings } from '@/api/admin-settings'
import { useI18n } from '@/i18n'

interface Props {
  slug: string
  issuer: string
  clientId: string
  scopes: string
}

function CopyBtn({ text }: { text: string }) {
  const { t } = useI18n()
  const [done, setDone] = useState(false)
  function copy() {
    if (!navigator.clipboard) return
    navigator.clipboard.writeText(text).catch(() => undefined)
    setDone(true)
    setTimeout(() => setDone(false), 2000)
  }
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={done ? t('copied') : t('copy')}
      title={done ? t('copied') : t('copy')}
      className="ml-1.5 shrink-0 text-muted-foreground transition-colors hover:text-foreground"
    >
      {done
        ? <CheckCircle2 size={12} className="text-emerald-600" aria-hidden="true" />
        : <Copy size={12} aria-hidden="true" />}
    </button>
  )
}

function CodeBox({ label, value, copy = false }: { label: string; value: string; copy?: boolean }) {
  return (
    <div>
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <div className="mt-1 flex items-start gap-2 rounded-md border border-border bg-background px-2.5 py-2">
        <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-foreground">
          {value}
        </code>
        {copy && <CopyBtn text={value} />}
      </div>
    </div>
  )
}

export default function AdminSsoInfoBlock({ slug, issuer, clientId, scopes }: Props) {
  const { t } = useI18n()
  const [effectiveUrl, setEffectiveUrl] = useState<string | null>(null)

  useEffect(() => {
    getGeneralSettings()
      .then(s => setEffectiveUrl(s.effective_public_base_url || s.public_base_url || null))
      .catch(() => undefined)
  }, [])

  const slugTrimmed = slug.trim()
  const publicBaseUrl = (effectiveUrl || '').replace(/\/+$/, '')
  const callbackUrl = slugTrimmed && publicBaseUrl
    ? `${publicBaseUrl}/api/v2/auth/oidc/${slugTrimmed}/callback`
    : null

  const displayScopes = scopes.trim() || 'openid email profile'

  return (
    <div className="rounded-lg border border-border bg-muted/40 p-3.5">
      <div className="mb-2.5 flex items-center gap-1.5">
        <Info size={12} className="shrink-0 text-muted-foreground" aria-hidden="true" />
        <p className="text-xs font-semibold text-foreground">{t('adminSsoInfoTitle')}</p>
      </div>

      <div className="flex flex-col gap-2">
        {effectiveUrl && (
          <CodeBox label={t('adminSsoInfoEffectiveUrl')} value={publicBaseUrl} />
        )}

        <div>
          <p className="text-xs font-medium text-muted-foreground">{t('adminSsoInfoCallbackUrl')}</p>
          {callbackUrl ? (
            <div className="mt-1 flex items-start gap-2 rounded-md border border-border bg-background px-2.5 py-2">
              <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-foreground">
                {callbackUrl}
              </code>
              <CopyBtn text={callbackUrl} />
            </div>
          ) : (
            <p className="text-xs italic text-muted-foreground">{t('adminSsoInfoSlugEmpty')}</p>
          )}
        </div>

        <div>
          <p className="text-xs font-medium text-muted-foreground">{t('adminSsoInfoRecommendedScopes')}</p>
          <div className="mt-1 flex items-center gap-2 rounded-md border border-border bg-background px-2.5 py-2">
            <code className="min-w-0 flex-1 font-mono text-xs text-foreground">{displayScopes}</code>
            <CopyBtn text={displayScopes} />
          </div>
        </div>

        {issuer.trim() && (
          <CodeBox label={t('adminSsoIssuer')} value={issuer.trim()} />
        )}

        {clientId.trim() && (
          <CodeBox label={t('adminSsoClientId')} value={clientId.trim()} />
        )}

        <p className="text-xs text-muted-foreground">{t('adminSsoInfoCallbackHint')}</p>
        <p className="text-xs text-muted-foreground">{t('adminSsoInfoKeycloakHint')}</p>
      </div>
    </div>
  )
}
