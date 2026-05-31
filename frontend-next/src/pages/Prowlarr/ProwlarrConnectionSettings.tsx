import { CheckCircle2, XCircle, Loader2, Copy } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { TestStatus } from './prowlarr.types'
import { QBT_CLIENT_URL } from './prowlarr.mock'

interface Props {
  testStatus: TestStatus
  onTest: () => void
}

const FIELD = 'flex-1 truncate rounded-md border border-input bg-muted/40 px-3 py-2 text-sm font-mono text-foreground'
const ROW_LABEL = 'w-28 shrink-0 text-xs font-medium text-muted-foreground pt-2'

function CopyButton({ value }: { value: string }) {
  return (
    <button
      type="button"
      aria-label={`Copy ${value}`}
      onClick={() => navigator.clipboard.writeText(value).catch(() => null)}
      className="flex items-center gap-1 rounded-md border border-input bg-background px-2 py-1.5 text-xs text-muted-foreground hover:bg-muted"
    >
      <Copy size={12} aria-hidden="true" />
    </button>
  )
}

export default function ProwlarrConnectionSettings({ testStatus, onTest }: Props) {
  return (
    <SectionCard
      title="qBittorrent Compatibility"
      description="Link2NAS exposes a qBittorrent-compatible API so Prowlarr can push downloads directly."
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-3 rounded-md border border-border bg-muted/20 p-4">
          <div className="flex items-start gap-3">
            <span className={ROW_LABEL}>Client URL</span>
            <div className="flex flex-1 items-center gap-2">
              <span className={FIELD}>{QBT_CLIENT_URL}</span>
              <CopyButton value={QBT_CLIENT_URL} />
            </div>
          </div>
          <div className="flex items-start gap-3">
            <span className={ROW_LABEL}>Username</span>
            <span className={`${FIELD} flex-1`}>any (not verified)</span>
          </div>
          <div className="flex items-start gap-3">
            <span className={ROW_LABEL}>Password</span>
            <span className="flex-1 rounded-md border border-input bg-muted/40 px-3 py-2 text-sm text-foreground">
              Your Link2NAS API key —{' '}
              <span className="font-mono text-xs">jobs:write</span> scope required
            </span>
          </div>
          <div className="flex items-start gap-3">
            <span className={ROW_LABEL}>Category</span>
            <div className="flex flex-1 items-center gap-2">
              <span className={`${FIELD} flex-1`}>prowlarr</span>
              <CopyButton value="prowlarr" />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button
            size="sm"
            variant="outline"
            onClick={onTest}
            disabled={testStatus === 'testing'}
          >
            {testStatus === 'testing' && (
              <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
            )}
            Test connection
          </Button>

          {testStatus === 'ok' && (
            <span className="flex items-center gap-1.5 text-sm text-green-700 dark:text-green-400">
              <CheckCircle2 size={14} aria-hidden="true" />
              Connection successful (mock)
            </span>
          )}
          {testStatus === 'fail' && (
            <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
              <XCircle size={14} aria-hidden="true" />
              Connection failed (mock)
            </span>
          )}
        </div>
      </div>
    </SectionCard>
  )
}
