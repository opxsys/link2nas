import { CheckCircle2, XCircle, Loader2, ShieldCheck } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { TestStatus } from './admin.types'
import { MOCK_SMTP } from './admin-settings.mock'

const ROW_LABEL = 'w-36 shrink-0 text-xs font-medium text-muted-foreground'
const ROW_VALUE = 'text-sm text-foreground'

interface Props {
  testStatus: TestStatus
  onTest: () => void
}

export default function AdminSmtp({ testStatus, onTest }: Props) {
  return (
    <SectionCard
      title="SMTP Configuration"
      description="Email delivery settings for notifications and invitations."
    >
      <div className="flex flex-col gap-5">
        <div className="flex flex-col gap-3 rounded-md border border-border bg-muted/20 p-4">
          <div className="flex items-center gap-3">
            <span className={ROW_LABEL}>Status</span>
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${MOCK_SMTP.configured ? 'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400' : 'border-border bg-muted text-muted-foreground'}`}>
              {MOCK_SMTP.configured ? <CheckCircle2 size={12} aria-hidden="true" /> : <XCircle size={12} aria-hidden="true" />}
              {MOCK_SMTP.configured ? 'Configured' : 'Not configured'}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className={ROW_LABEL}>Provider</span>
            <span className={ROW_VALUE}>{MOCK_SMTP.provider}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className={ROW_LABEL}>Host / Port</span>
            <span className={`${ROW_VALUE} font-mono text-xs`}>{MOCK_SMTP.host}:{MOCK_SMTP.port}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className={ROW_LABEL}>From address</span>
            <span className={`${ROW_VALUE} font-mono text-xs`}>{MOCK_SMTP.from}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className={ROW_LABEL}>TLS</span>
            <span className="inline-flex items-center gap-1 text-xs text-green-700 dark:text-green-400">
              {MOCK_SMTP.tlsEnabled && <ShieldCheck size={13} aria-hidden="true" />}
              {MOCK_SMTP.tlsEnabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button size="sm" variant="outline" onClick={onTest} disabled={testStatus === 'sending'}>
            {testStatus === 'sending' && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            Send test email
          </Button>
        </div>

        {testStatus === 'sent' && (
          <div className="flex items-center gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2.5 text-sm text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
            <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
            Test email sent (mock) — check your inbox.
          </div>
        )}
        {testStatus === 'failed' && (
          <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={15} className="shrink-0" aria-hidden="true" />
            Test delivery failed (mock) — check SMTP settings.
          </div>
        )}
      </div>
    </SectionCard>
  )
}
