import { CheckCircle2, XCircle, MinusCircle, ExternalLink } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { ProwlarrConnectionStatus, ProwlarrOpenMode } from './prowlarr.types'

interface Props {
  url: string
  connectionStatus: ProwlarrConnectionStatus
  openMode: ProwlarrOpenMode
  setAsHomePage: boolean
  onOpenModeChange: (mode: ProwlarrOpenMode) => void
  onHomePageToggle: (val: boolean) => void
}

const STATUS_CONFIG: Record<ProwlarrConnectionStatus, { label: string; icon: React.ReactNode; className: string }> = {
  connected: {
    label: 'Connected',
    icon: <CheckCircle2 size={14} aria-hidden="true" />,
    className: 'text-green-700 bg-green-50 border-green-200 dark:text-green-400 dark:bg-green-950 dark:border-green-800',
  },
  disconnected: {
    label: 'Unreachable',
    icon: <XCircle size={14} aria-hidden="true" />,
    className: 'text-red-700 bg-red-50 border-red-200 dark:text-red-400 dark:bg-red-950 dark:border-red-800',
  },
  unconfigured: {
    label: 'Not configured',
    icon: <MinusCircle size={14} aria-hidden="true" />,
    className: 'text-muted-foreground bg-muted border-border',
  },
}

const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

export default function ProwlarrStatusCard({
  url,
  connectionStatus,
  openMode,
  setAsHomePage,
  onOpenModeChange,
  onHomePageToggle,
}: Props) {
  const s = STATUS_CONFIG[connectionStatus]

  return (
    <SectionCard title="Prowlarr Connection">
      <div className="flex flex-col gap-5">
        <div className="flex items-center gap-3">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${s.className}`}
          >
            {s.icon}
            {s.label}
          </span>
        </div>

        <div>
          <p className="mb-1 text-xs font-medium text-foreground">Prowlarr URL</p>
          <div className="flex items-center gap-2">
            <span className="flex-1 truncate rounded-md border border-input bg-muted/40 px-3 py-2 text-sm text-foreground">
              {url}
            </span>
            <a
              href="#"
              onClick={(e) => e.preventDefault()}
              aria-label="Open Prowlarr (mock)"
              className="flex items-center gap-1 rounded-md border border-input bg-background px-3 py-2 text-xs text-muted-foreground hover:bg-muted"
            >
              <ExternalLink size={13} aria-hidden="true" />
              Open
            </a>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Configure this URL in Settings → Prowlarr.
          </p>
        </div>

        <div>
          <label htmlFor="prowlarr-open-mode" className="mb-1.5 block text-xs font-medium text-foreground">
            Open mode
          </label>
          <select
            id="prowlarr-open-mode"
            value={openMode}
            onChange={(e) => onOpenModeChange(e.target.value as ProwlarrOpenMode)}
            className={SELECT}
          >
            <option value="iframe">Iframe (embedded)</option>
            <option value="newtab">Open in new tab</option>
          </select>
        </div>

        <label className="flex cursor-pointer items-center gap-3">
          <input
            type="checkbox"
            checked={setAsHomePage}
            onChange={(e) => onHomePageToggle(e.target.checked)}
            className="h-4 w-4 rounded border-input accent-primary"
          />
          <span className="text-sm text-foreground">Set Prowlarr as home page</span>
        </label>
      </div>
    </SectionCard>
  )
}
