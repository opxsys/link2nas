import { useState } from 'react'
import { Info } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { MOCK_PROWLARR } from './settings.mock'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

export default function ProwlarrSettings() {
  const [enabled, setEnabled] = useState(MOCK_PROWLARR.enabled)
  const [url, setUrl] = useState(MOCK_PROWLARR.url)
  const [openMode, setOpenMode] = useState<'iframe' | 'newtab'>(MOCK_PROWLARR.openMode)
  const [homePage, setHomePage] = useState(MOCK_PROWLARR.setAsHomePage)
  const [saved, setSaved] = useState(false)

  function handleSave() {
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="Prowlarr Integration">
        <div className="flex flex-col gap-5">
          <label className="flex cursor-pointer items-start gap-3">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-input accent-primary"
            />
            <div>
              <p className="text-sm font-medium text-foreground">Enable Prowlarr</p>
              <p className="text-xs text-muted-foreground">
                Show Prowlarr in the Prowlarr page when a URL is configured.
              </p>
            </div>
          </label>

          <div>
            <label htmlFor="prowlarr-url" className={LABEL}>Prowlarr URL</label>
            <input
              id="prowlarr-url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://nas.local:9696"
              disabled={!enabled}
              className={INPUT}
            />
          </div>

          <div>
            <label htmlFor="prowlarr-open-mode" className={cn(LABEL, !enabled && 'opacity-50')}>
              Open mode
            </label>
            <select
              id="prowlarr-open-mode"
              value={openMode}
              onChange={(e) => setOpenMode(e.target.value as 'iframe' | 'newtab')}
              disabled={!enabled}
              className={SELECT}
            >
              <option value="iframe">Iframe (embedded)</option>
              <option value="newtab">Open in new tab</option>
            </select>
          </div>

          <label className={cn('flex cursor-pointer items-center gap-3', !enabled && 'opacity-50')}>
            <input
              type="checkbox"
              checked={homePage}
              onChange={(e) => setHomePage(e.target.checked)}
              disabled={!enabled}
              className="h-4 w-4 rounded border-input accent-primary disabled:opacity-50"
            />
            <span className="text-sm text-foreground">Set Prowlarr as home page</span>
          </label>

          <div className="flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
            <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
            No Prowlarr login or password is stored by Link2NAS.
            The iframe or tab will use your existing browser session.
          </div>
        </div>
      </SectionCard>

      <div className="flex items-center gap-3">
        <Button size="sm" onClick={handleSave}>Save changes</Button>
        {saved && (
          <span className="text-xs text-muted-foreground">Mock changes only — not persisted.</span>
        )}
      </div>
    </div>
  )
}
