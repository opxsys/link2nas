import { Link } from 'react-router-dom'
import { ExternalLink, Settings, Loader2 } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import { useIntegrationSettings, isProwlarrAvailable } from '@/lib/useIntegrationSettings'

function NotConfiguredState() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed border-border bg-muted/20 py-16 text-center">
      <Settings size={32} className="text-muted-foreground" aria-hidden="true" />
      <div>
        <p className="text-sm font-medium text-foreground">{t('prowlarrNotConfigured')}</p>
        <p className="mt-1 text-xs text-muted-foreground">{t('prowlarrNotConfiguredDesc')}</p>
      </div>
      <Button asChild size="sm" variant="outline">
        <Link to="/settings">
          <Settings size={13} className="mr-1.5" aria-hidden="true" />
          {t('goToSettingsProwlarr')}
        </Link>
      </Button>
    </div>
  )
}

export default function Prowlarr() {
  const { t } = useI18n()
  const { settings, loading } = useIntegrationSettings()

  if (loading) {
    return (
      <>
        <PageHeader title={t('navProwlarr')} description={t('prowlarrDesc')} />
        <div className="flex items-center gap-2 py-12 text-muted-foreground">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
          <span className="text-sm">{t('loading')}</span>
        </div>
      </>
    )
  }

  const available  = isProwlarrAvailable(settings)
  const mode       = settings?.prowlarr_open_mode ?? 'both'
  const url        = settings?.prowlarr_url ?? ''
  const showIframe = available && (mode === 'iframe' || mode === 'both')
  const showNewTab = available && (mode === 'new_tab' || mode === 'both')

  return (
    <>
      <PageHeader
        title={t('navProwlarr')}
        description={t('prowlarrDesc')}
      />

      <div className="flex flex-col gap-6">
        {!available ? (
          <NotConfiguredState />
        ) : (
          <>
            {showNewTab && (
              <div className="flex items-center gap-3">
                <Button asChild variant="outline">
                  <a href={url} target="_blank" rel="noopener noreferrer">
                    <ExternalLink size={14} className="mr-1.5" aria-hidden="true" />
                    {t('openProwlarrNewTab')}
                  </a>
                </Button>
                <span className="font-mono text-xs text-muted-foreground">{url}</span>
              </div>
            )}

            {showIframe && (
              <div
                className="overflow-hidden rounded-lg border border-border"
                style={{ height: 'calc(100vh - 220px)', minHeight: 400 }}
              >
                <iframe src={url} title={t('navProwlarr')} className="h-full w-full" allow="fullscreen" />
              </div>
            )}
          </>
        )}

      </div>
    </>
  )
}
