import { AlertTriangle, AlertCircle, Info, CheckCircle2, XCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { SystemEventSeverity } from './admin.types'
import { MOCK_SYSTEM_EVENT_TYPES, MOCK_SYSTEM_EVENTS } from './admin-system.mock'

const SEV_CONFIG: Record<SystemEventSeverity, { icon: React.ReactNode; className: string; badge: string }> = {
  error:   { icon: <AlertCircle size={13} aria-hidden="true" />,   className: 'text-red-600 dark:text-red-400',     badge: 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400' },
  warning: { icon: <AlertTriangle size={13} aria-hidden="true" />, className: 'text-orange-600 dark:text-orange-400', badge: 'border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950 dark:text-orange-400' },
  info:    { icon: <Info size={13} aria-hidden="true" />,           className: 'text-blue-600 dark:text-blue-400',   badge: 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400' },
}

const PILL = 'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium'

export default function AdminSystemEvents() {
  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="Event Types" description="Tracked system event codes with severity and dedup settings.">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Code</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Severity</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Dedup</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Rate limited</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_SYSTEM_EVENT_TYPES.map((t) => {
                const sev = SEV_CONFIG[t.severity]
                return (
                  <tr key={t.code} className="border-b border-border last:border-0 hover:bg-muted/30">
                    <td className="px-4 py-2.5 font-mono text-xs text-foreground">{t.code}</td>
                    <td className="px-4 py-2.5">
                      <span className={`${PILL} ${sev.badge}`}>{sev.icon}{t.severity}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{t.deduplicated ? 'Yes' : 'No'}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{t.rateLimited ? 'Yes' : 'No'}</td>
                    <td className="px-4 py-2.5">
                      {t.enabled
                        ? <CheckCircle2 size={14} className="text-green-600 dark:text-green-400" aria-label="Enabled" />
                        : <XCircle size={14} className="text-muted-foreground" aria-label="Disabled" />
                      }
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <SectionCard title="Recent System Events" description="Latest system-level events logged by Link2NAS.">
        <ul className="divide-y divide-border">
          {MOCK_SYSTEM_EVENTS.map((ev) => {
            const sev = SEV_CONFIG[ev.severity]
            return (
              <li key={ev.id} className="flex items-start gap-3 py-3">
                <span className={`mt-0.5 shrink-0 ${sev.className}`}>{sev.icon}</span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-mono text-xs text-foreground">{ev.code}</span>
                    <span className="text-xs text-muted-foreground">{ev.timestamp}</span>
                    {ev.resolved && (
                      <span className="inline-flex items-center gap-1 rounded-full border border-green-200 bg-green-50 px-1.5 py-0.5 text-xs text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
                        <CheckCircle2 size={9} aria-hidden="true" />Resolved
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">{ev.message}</p>
                </div>
              </li>
            )
          })}
        </ul>
      </SectionCard>
    </div>
  )
}
