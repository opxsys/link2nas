import { CheckCircle2, XCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { MOCK_SECURITY } from './admin-settings.mock'

const ROW = 'flex items-center justify-between gap-4 border-b border-border py-2.5 last:border-0'
const LABEL = 'text-sm text-muted-foreground'
const VALUE = 'text-sm font-medium text-foreground'

function BoolValue({ value, trueLabel = 'Enabled', falseLabel = 'Disabled' }: { value: boolean; trueLabel?: string; falseLabel?: string }) {
  return value ? (
    <span className="inline-flex items-center gap-1 text-sm text-green-700 dark:text-green-400">
      <CheckCircle2 size={13} aria-hidden="true" /> {trueLabel}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-sm text-muted-foreground">
      <XCircle size={13} aria-hidden="true" /> {falseLabel}
    </span>
  )
}

export default function AdminSecurity() {
  const s = MOCK_SECURITY
  return (
    <div className="flex flex-col gap-4">
      <SectionCard title="Session & Tokens">
        <div>
          <div className={ROW}><span className={LABEL}>Token TTL</span><span className={VALUE}>{s.tokenTtlDays} days</span></div>
          <div className={ROW}><span className={LABEL}>Session inactivity timeout</span><span className={VALUE}>{s.sessionInactivityMinutes} minutes</span></div>
        </div>
      </SectionCard>

      <SectionCard title="Password Policy">
        <div>
          <div className={ROW}><span className={LABEL}>Minimum length</span><span className={VALUE}>{s.passwordMinLength} characters</span></div>
          <div className={ROW}><span className={LABEL}>Require uppercase</span><BoolValue value={s.requireUppercase} /></div>
          <div className={ROW}><span className={LABEL}>Require numbers</span><BoolValue value={s.requireNumbers} /></div>
        </div>
      </SectionCard>

      <SectionCard title="Rate Limiting">
        <div>
          <div className={ROW}><span className={LABEL}>Rate limiting</span><BoolValue value={s.rateLimitEnabled} /></div>
          <div className={ROW}><span className={LABEL}>Limit per minute</span><span className={VALUE}>{s.rateLimitPerMinute} requests</span></div>
        </div>
      </SectionCard>
    </div>
  )
}
