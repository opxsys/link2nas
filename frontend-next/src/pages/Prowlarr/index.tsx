import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink, Settings, Loader2 } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import { useIntegrationSettings, isProwlarrAvailable } from '@/lib/useIntegrationSettings'
import ProwlarrConnectionSettings from './ProwlarrConnectionSettings'
import ProwlarrQbittorrentGuide from './ProwlarrQbittorrentGuide'
import ProwlarrRecentSubmissions from './ProwlarrRecentSubmissions'
import type { TestStatus } from './prowlarr.types'

function NotConfiguredState() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed border-border bg-muted/20 py-16 text-center">
      <Settings size={32} className="text-muted-foreground" aria-hidden="true" />
      <div>
        <p className="text-sm font-medium text-foreground">Prowlarr is not configured</p>
        <p className="mt-1 text-xs text-muted-foreground">
          Enable Prowlarr and set a URL in Settings to use this page.
        </p>
      </div>
      <Button asChild size="sm" variant="outline">
        <Link to="/settings">
          <Settings size={13} className="mr-1.5" aria-hidden="true" />
          Go to Settings → Prowlarr
        </Link>
      </Button>
    </div>
  )
}

export default function Prowlarr() {
  const { settings, loading } = useIntegrationSettings()
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')

  function runTest() {
    setTestStatus('testing')
    setTimeout(() => setTestStatus('ok'), 1500)
  }

  if (loading) {
    return (
      <>
        <PageHeader title="Prowlarr" description="Browse and submit via your Prowlarr instance." />
        <div className="flex items-center gap-2 py-12 text-muted-foreground">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
          <span className="text-sm">Loading…</span>
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
        title="Prowlarr"
        description="Browse and submit via your Prowlarr instance. Configure the integration in Settings → Prowlarr."
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
                    Open Prowlarr in new tab
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
                <iframe src={url} title="Prowlarr" className="h-full w-full" allow="fullscreen" />
              </div>
            )}
          </>
        )}

        <ProwlarrConnectionSettings testStatus={testStatus} onTest={runTest} />
        <ProwlarrQbittorrentGuide />
        <ProwlarrRecentSubmissions />
      </div>
    </>
  )
}
