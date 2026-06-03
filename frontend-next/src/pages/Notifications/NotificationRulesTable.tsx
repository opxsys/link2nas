import { Link } from 'react-router-dom'
import { Settings } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { NotificationRule, NotificationConfig } from './notifications.types'

const CHANNEL_LABEL: Record<string, string> = {
  email: 'Email', gotify: 'Gotify', webhook: 'Webhook',
}

const SEVERITY_LABEL: Record<string, string> = {
  info: 'Info+', warning: 'Warning+', error: 'Error+', critical: 'Critical only',
}

interface Props {
  rules: NotificationRule[]
  configs: NotificationConfig[]
  loading: boolean
  error: string | null
  onToggle: (id: string, enabled: boolean) => Promise<void>
}

function RuleRow({
  rule, configName, onToggle,
}: {
  rule: NotificationRule
  configName: string
  onToggle: () => void
}) {
  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-4 py-2.5 text-sm text-foreground">{rule.name}</td>
      <td className="px-4 py-2.5 text-xs font-mono text-muted-foreground">
        {rule.event_types.length
          ? rule.event_types.join(', ')
          : <span className="italic">All events</span>}
      </td>
      <td className="px-4 py-2.5 text-sm text-muted-foreground">{configName}</td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">
        {SEVERITY_LABEL[rule.severity_min] ?? rule.severity_min}
      </td>
      <td className="px-4 py-2.5">
        <label className="flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            checked={rule.is_enabled}
            onChange={onToggle}
            className="h-4 w-4 rounded border-input accent-primary"
            aria-label={`${rule.is_enabled ? 'Disable' : 'Enable'} rule: ${rule.name}`}
          />
          <span className="text-xs text-muted-foreground">{rule.is_enabled ? 'On' : 'Off'}</span>
        </label>
      </td>
    </tr>
  )
}

export default function NotificationRulesTable({ rules, configs, loading, error, onToggle }: Props) {
  function configName(configId: string): string {
    const cfg = configs.find(c => c.id === configId)
    return cfg ? `${cfg.name} (${CHANNEL_LABEL[cfg.channel] ?? cfg.channel})` : '—'
  }

  return (
    <SectionCard
      title="Notification Rules"
      description="Active rules that trigger notifications."
      actions={
        <Link
          to="/settings?section=notifications"
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Settings size={12} aria-hidden="true" />
          Manage in Settings
        </Link>
      }
    >
      {loading && (
        <p className="py-6 text-sm text-muted-foreground">Loading rules…</p>
      )}
      {!loading && error && (
        <p className="py-4 text-sm text-destructive">{error}</p>
      )}
      {!loading && !error && rules.length === 0 && (
        <p className="py-4 text-sm italic text-muted-foreground">
          No notification rules configured. <Link to="/settings?section=notifications" className="underline hover:text-foreground">Add one in Settings → Notifications.</Link>
        </p>
      )}
      {!loading && !error && rules.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Name</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Events</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Channel</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Min severity</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <RuleRow
                  key={rule.id}
                  rule={rule}
                  configName={configName(rule.config_id)}
                  onToggle={() => onToggle(rule.id, !rule.is_enabled)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  )
}
