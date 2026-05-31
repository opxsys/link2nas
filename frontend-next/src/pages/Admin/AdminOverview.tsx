import { Users, UserCheck, UserPlus, AlertTriangle, Mail, ShieldCheck, Cpu, Trash2 } from 'lucide-react'
import MetricCard from '@/components/common/MetricCard'
import SectionCard from '@/components/common/SectionCard'
import { MOCK_ADMIN_SUMMARY } from './admin-system.mock'
import { MOCK_SMTP } from './admin-settings.mock'
import { MOCK_RUNTIME } from './admin-settings.mock'

const runningCount = MOCK_RUNTIME.filter((r) => r.status === 'running').length

const HEALTH_ITEMS = [
  {
    label: 'SMTP',
    icon: Mail,
    ok: MOCK_SMTP.configured,
    note: MOCK_SMTP.configured ? `${MOCK_SMTP.host}:${MOCK_SMTP.port}` : 'Not configured',
  },
  {
    label: 'Security',
    icon: ShieldCheck,
    ok: true,
    note: 'Policy active',
  },
  {
    label: 'Runtime',
    icon: Cpu,
    ok: runningCount >= 3,
    note: `${runningCount}/${MOCK_RUNTIME.length} running`,
  },
  {
    label: 'Cleanup',
    icon: Trash2,
    ok: true,
    note: 'Last run 28/05/2026',
  },
]

export default function AdminOverview() {
  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <MetricCard label="Total Users"          value={MOCK_ADMIN_SUMMARY.totalUsers}         icon={Users}     description="All accounts" />
        <MetricCard label="Active Users"          value={MOCK_ADMIN_SUMMARY.activeUsers}        icon={UserCheck} description="Enabled accounts"   iconClassName="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" />
        <MetricCard label="Pending Invitations"   value={MOCK_ADMIN_SUMMARY.pendingInvitations} icon={UserPlus}  description="Awaiting first login" iconClassName="bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400" />
        <MetricCard label="System Events Today"   value={MOCK_ADMIN_SUMMARY.systemEventsToday}  icon={AlertTriangle} description="Warnings and errors" iconClassName="bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" />
      </div>

      <SectionCard title="Quick Health">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {HEALTH_ITEMS.map(({ label, icon: Icon, ok, note }) => (
            <div key={label} className="flex items-start gap-3 rounded-md border border-border bg-muted/20 p-3">
              <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${ok ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'}`}>
                <Icon size={15} aria-hidden="true" />
              </div>
              <div>
                <p className="text-sm font-medium text-foreground">{label}</p>
                <p className="text-xs text-muted-foreground">{note}</p>
              </div>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  )
}
