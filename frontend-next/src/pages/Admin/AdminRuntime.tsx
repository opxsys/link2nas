import { CheckCircle2, XCircle, AlertCircle, Timer } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { RuntimeComponent, RuntimeStatus } from './admin.types'
import { MOCK_RUNTIME } from './admin-settings.mock'

const STATUS_CONFIG: Record<RuntimeStatus, { label: string; icon: React.ReactNode; className: string }> = {
  running: {
    label: 'Running',
    icon: <CheckCircle2 size={13} aria-hidden="true" />,
    className: 'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400',
  },
  stopped: {
    label: 'Stopped',
    icon: <XCircle size={13} aria-hidden="true" />,
    className: 'border-border bg-muted text-muted-foreground',
  },
  error: {
    label: 'Error',
    icon: <AlertCircle size={13} aria-hidden="true" />,
    className: 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400',
  },
}

function RuntimeCard({ component }: { component: RuntimeComponent }) {
  const s = STATUS_CONFIG[component.status]
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border bg-card p-4 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-semibold text-foreground">{component.name}</span>
        <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${s.className}`}>
          {s.icon}{s.label}
        </span>
      </div>
      <p className="text-xs text-muted-foreground">{component.description}</p>
      {component.interval && (
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
          <Timer size={11} aria-hidden="true" />
          {component.interval}
        </span>
      )}
    </div>
  )
}

export default function AdminRuntime() {
  return (
    <SectionCard title="Runtime Components" description="Status of background workers and schedulers.">
      <div className="grid gap-3 sm:grid-cols-2">
        {MOCK_RUNTIME.map((c) => <RuntimeCard key={c.id} component={c} />)}
      </div>
    </SectionCard>
  )
}
