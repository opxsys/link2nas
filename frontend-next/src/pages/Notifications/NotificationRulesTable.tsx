import { Trash2, Loader2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { NotificationRule, NotificationConfig } from './notifications.types'

const CHANNEL_LABEL: Record<string, string> = {
  email: 'Email',
  gotify: 'Gotify',
  webhook: 'Webhook',
}

const SEVERITY_LABEL: Record<string, string> = {
  info: 'Info+',
  warning: 'Warning+',
  error: 'Error+',
  critical: 'Critical only',
}

interface Props {
  rules: NotificationRule[]
  configs: NotificationConfig[]
  loading: boolean
  error: string | null
  onToggle: (id: string, enabled: boolean) => Promise<void>
  onDelete: (id: string) => Promise<void>
}

function RuleRow({
  rule,
  configName,
  onToggle,
  onDelete,
}: {
  rule: NotificationRule
  configName: string
  onToggle: () => void
  onDelete: () => void
}) {
  const eventLabel = rule.event_types.length
    ? rule.event_types.join(', ')
    : <span className="italic text-muted-foreground">All events</span>

  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-4 py-2.5 text-sm text-foreground">{rule.name}</td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{eventLabel}</td>
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
      <td className="px-4 py-2.5">
        <Button
          variant="ghost"
          size="icon"
          aria-label={`Delete rule: ${rule.name}`}
          className="h-7 w-7 text-destructive hover:text-destructive"
          onClick={onDelete}
        >
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </td>
    </tr>
  )
}

export default function NotificationRulesTable({ rules, configs, loading, error, onToggle, onDelete }: Props) {
  function configName(configId: string): string {
    const cfg = configs.find(c => c.id === configId)
    if (!cfg) return configId ? '—' : '—'
    return `${cfg.name} (${CHANNEL_LABEL[cfg.channel] ?? cfg.channel})`
  }

  return (
    <SectionCard
      title="Notification Rules"
      description="Configure which events trigger notifications and on which channel."
      actions={
        <Button size="sm" variant="outline" disabled>
          Add rule
        </Button>
      }
    >
      {loading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          Loading rules…
        </div>
      )}
      {!loading && error && (
        <p className="py-4 text-sm text-destructive">{error}</p>
      )}
      {!loading && !error && rules.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground italic">No notification rules configured.</p>
      )}
      {!loading && !error && rules.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Name</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Event types</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Channel</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Min severity</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Enabled</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <RuleRow
                  key={rule.id}
                  rule={rule}
                  configName={configName(rule.config_id)}
                  onToggle={() => onToggle(rule.id, !rule.is_enabled)}
                  onDelete={() => onDelete(rule.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  )
}
