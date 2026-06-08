import { useState, useEffect } from 'react'
import { Info, Copy, CheckCircle2 } from 'lucide-react'
import { getGeneralSettings } from '@/api/admin-settings'
import { useI18n } from '@/i18n'

const CF_HEADER = 'Cf-Access-Jwt-Assertion'

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

export default function AdminIdentityProxyInfoBlock() {
  const { t } = useI18n()
  const [effectiveUrl, setEffectiveUrl] = useState<string | null>(null)

  useEffect(() => {
    getGeneralSettings()
      .then(s => setEffectiveUrl(s.effective_public_base_url || s.public_base_url || null))
      .catch(() => undefined)
  }, [])

  const publicBaseUrl = (effectiveUrl || '').replace(/\/+$/, '')

  return (
    <div className="rounded-lg border border-border bg-muted/40 p-3.5">
      <div className="mb-2.5 flex items-center gap-1.5">
        <Info size={12} className="shrink-0 text-muted-foreground" aria-hidden="true" />
        <p className="text-xs font-semibold text-foreground">{t('adminIpInfoTitle')}</p>
      </div>

      <p className="mb-3 text-xs text-muted-foreground">{t('adminIpInfoDesc')}</p>

      <div className="flex flex-col gap-2">
        {publicBaseUrl && (
          <div>
            <p className="text-xs font-medium text-muted-foreground">{t('adminIpInfoPublicUrl')}</p>
            <div className="mt-1 flex items-start gap-2 rounded-md border border-border bg-background px-2.5 py-2">
              <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-foreground">
                {publicBaseUrl}
              </code>
              <CopyBtn text={publicBaseUrl} />
            </div>
          </div>
        )}

        {publicBaseUrl && (
          <div>
            <p className="text-xs font-medium text-muted-foreground">{t('adminIpInfoAppUrl')}</p>
            <div className="mt-1 rounded-md border border-border bg-background px-2.5 py-2">
              <code className="whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-foreground">
                {publicBaseUrl}
              </code>
            </div>
          </div>
        )}

        <div>
          <p className="text-xs font-medium text-muted-foreground">{t('adminIpInfoCallback')}</p>
          <p className="text-xs italic text-muted-foreground">{t('adminIpInfoCallbackNA')}</p>
        </div>

        <div>
          <p className="text-xs font-medium text-muted-foreground">{t('adminIpInfoHeader')}</p>
          <div className="mt-1 flex items-center gap-2 rounded-md border border-border bg-background px-2.5 py-2">
            <code className="min-w-0 flex-1 font-mono text-xs text-foreground">{CF_HEADER}</code>
            <CopyBtn text={CF_HEADER} />
          </div>
        </div>

        <div>
          <p className="text-xs font-medium text-muted-foreground">{t('adminIpInfoCfFields')}</p>
          <ul className="mt-0.5 list-disc pl-4 text-xs text-muted-foreground">
            <li>{t('adminIpTeamDomain')}</li>
            <li>{t('adminIpAudience')}</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
