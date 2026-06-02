import { useState, useEffect } from 'react'
import { Info, CheckCircle2, XCircle, Loader2, AlertCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { updateIntegrationSettings } from '@/api/integration-settings'
import { useIntegrationSettings, invalidateIntegrationSettings } from '@/lib/useIntegrationSettings'
import type { ProwlarrOpenMode } from '@/api/integration-settings'
import ProwlarrQbittorrentGuide from '@/pages/Prowlarr/ProwlarrQbittorrentGuide'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

export default function ProwlarrSettings() {
  const { settings, loading } = useIntegrationSettings()

  const [enabled, setEnabled]   = useState(false)
  const [url, setUrl]           = useState('')
  const [openMode, setOpenMode] = useState<ProwlarrOpenMode>('both')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')

  useEffect(() => {
    if (!settings) return
    setEnabled(settings.prowlarr_enabled)
    setUrl(settings.prowlarr_url)
    setOpenMode(settings.prowlarr_open_mode)
  }, [settings])

  async function handleSave() {
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      await updateIntegrationSettings({
        prowlarr_enabled: enabled,
        prowlarr_url: url.trim(),
        prowlarr_open_mode: openMode,
      })
      invalidateIntegrationSettings()
      setSaveStatus('saved')
      setSaveMessage('Prowlarr settings saved.')
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : 'Save failed.')
    }
  }

  if (loading && !settings) {
    return (
      <div className="flex items-center gap-2 py-8 text-muted-foreground">
        <Loader2 size={18} className="animate-spin" aria-hidden="true" />
        <span className="text-sm">Loading…</span>
      </div>
    )
  }

  const busy = saveStatus === 'saving'

  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="Prowlarr Integration">
        <div className="flex flex-col gap-5">
          <label className="flex cursor-pointer items-start gap-3">
            <input type="checkbox" checked={enabled} disabled={busy}
              onChange={(e) => setEnabled(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-input accent-primary disabled:opacity-50" />
            <div>
              <p className="text-sm font-medium text-foreground">Enable Prowlarr</p>
              <p className="text-xs text-muted-foreground">
                Show Prowlarr in the sidebar when a URL is configured.
              </p>
            </div>
          </label>

          <div>
            <label htmlFor="prowlarr-url" className={LABEL}>Prowlarr URL</label>
            <input id="prowlarr-url" type="url" value={url} disabled={!enabled || busy}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://nas.local:9696" className={INPUT} />
          </div>

          <div>
            <label htmlFor="prowlarr-open-mode" className={cn(LABEL, !enabled && 'opacity-50')}>
              Open mode
            </label>
            <select id="prowlarr-open-mode" value={openMode} disabled={!enabled || busy}
              onChange={(e) => setOpenMode(e.target.value as ProwlarrOpenMode)}
              className={SELECT}>
              <option value="iframe">Iframe (embedded)</option>
              <option value="new_tab">Open in new tab</option>
              <option value="both">Both (iframe + new tab button)</option>
            </select>
          </div>

          {enabled && (
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
              <AlertCircle size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              Enabling Prowlarr requires an active API key with the{' '}
              <code className="font-mono">qbittorrent:write</code> scope (Settings → API Keys).
            </div>
          )}

          <div className="flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
            <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
            No Prowlarr login or password is stored by Link2NAS.
            The iframe or tab will use your existing browser session.
          </div>
        </div>
      </SectionCard>

      <div className="flex flex-wrap items-center gap-3">
        <Button size="sm" onClick={handleSave} disabled={busy}>
          {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
          Save changes
        </Button>
        {saveStatus === 'saved' && (
          <span className="flex items-center gap-1.5 text-sm text-green-700 dark:text-green-400">
            <CheckCircle2 size={14} aria-hidden="true" /> {saveMessage}
          </span>
        )}
        {saveStatus === 'error' && (
          <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
            <XCircle size={14} aria-hidden="true" /> {saveMessage}
          </span>
        )}
      </div>

      <ProwlarrQbittorrentGuide />
    </div>
  )
}
