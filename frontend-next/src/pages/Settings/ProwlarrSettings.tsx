import { useState, useEffect, useRef } from 'react'
import { Info, CheckCircle2, XCircle, Loader2, AlertCircle, KeyRound, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { updateIntegrationSettings } from '@/api/integration-settings'
import { useIntegrationSettings, invalidateIntegrationSettings } from '@/lib/useIntegrationSettings'
import { useQbtWriteKeyStatus, invalidateQbtWriteKeyStatus } from '@/lib/useQbtWriteKeyStatus'
import type { ProwlarrOpenMode } from '@/api/integration-settings'
import ProwlarrQbittorrentGuide from '@/pages/Prowlarr/ProwlarrQbittorrentGuide'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

interface Props {
  onGoToApiKeys?: () => void
}

export default function ProwlarrSettings({ onGoToApiKeys }: Props) {
  const { settings, loading } = useIntegrationSettings()
  const keyStatus = useQbtWriteKeyStatus()

  const [enabled, setEnabled]   = useState(false)
  const [url, setUrl]           = useState('')
  const [openMode, setOpenMode] = useState<ProwlarrOpenMode>('both')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!settings) return
    setEnabled(settings.prowlarr_enabled)
    setUrl(settings.prowlarr_url)
    setOpenMode(settings.prowlarr_open_mode)
  }, [settings])

  useEffect(() => () => { if (successTimer.current) clearTimeout(successTimer.current) }, [])

  const canEnable = keyStatus === 'ok'

  async function handleSave() {
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      await updateIntegrationSettings({
        prowlarr_enabled: canEnable ? enabled : false,
        prowlarr_url: url.trim(),
        prowlarr_open_mode: openMode,
      })
      invalidateIntegrationSettings()
      setSaveStatus('saved')
      setSaveMessage('Prowlarr settings saved.')
      if (successTimer.current) clearTimeout(successTimer.current)
      successTimer.current = setTimeout(() => setSaveStatus('idle'), 4000)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Save failed.'
      setSaveStatus('error')
      setSaveMessage(message)
      if (message.toLowerCase().includes('qbittorrent:write') || message.toLowerCase().includes('api key')) {
        setEnabled(false)
        invalidateQbtWriteKeyStatus()
      }
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
  const checkboxDisabled = busy || !canEnable

  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="Prowlarr Integration">
        <div className="flex flex-col gap-5">

          {keyStatus === 'missing' && (
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
              <KeyRound size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              <span>
                No active API key with the{' '}
                <code className="font-mono">qbittorrent:write</code> scope was found.
                Create one before enabling Prowlarr.{' '}
                {onGoToApiKeys ? (
                  <button
                    type="button"
                    onClick={onGoToApiKeys}
                    className="underline underline-offset-2 hover:opacity-80"
                  >
                    Go to API Keys →
                  </button>
                ) : null}
              </span>
            </div>
          )}

          {keyStatus === 'error' && (
            <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <AlertCircle size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              Could not load API keys. Prowlarr cannot be enabled until key status can be verified.
            </div>
          )}

          <label className={cn('flex items-start gap-3', checkboxDisabled && !busy ? 'cursor-not-allowed opacity-60' : 'cursor-pointer')}>
            <input
              type="checkbox"
              checked={enabled && canEnable}
              disabled={checkboxDisabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-input accent-primary disabled:opacity-50"
            />
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

          <div className="flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
            <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
            No Prowlarr login or password is stored by Link2NAS.
            The iframe or tab will use your existing browser session.
          </div>
        </div>
      </SectionCard>

      <div className="flex flex-col gap-3">
        <div>
          <Button size="sm" onClick={handleSave} disabled={busy}>
            {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            Save changes
          </Button>
        </div>
        {saveStatus === 'saved' && (
          <div className="flex items-center justify-between gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
            <span className="flex items-center gap-2">
              <CheckCircle2 size={14} aria-hidden="true" />
              {saveMessage}
            </span>
            <button onClick={() => setSaveStatus('idle')} className="shrink-0 opacity-60 hover:opacity-100" aria-label="Dismiss">
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        )}
        {saveStatus === 'error' && (
          <div className="flex items-center justify-between gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <span className="flex items-center gap-2">
              <XCircle size={14} aria-hidden="true" />
              {saveMessage}
            </span>
            <button onClick={() => setSaveStatus('idle')} className="shrink-0 opacity-60 hover:opacity-100" aria-label="Dismiss">
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        )}
      </div>

      <ProwlarrQbittorrentGuide />
    </div>
  )
}
