import { Pencil, Trash2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { NotificationRule } from './notifications.types'
import { MOCK_RULES } from './notifications.mock'

const CHANNEL_LABEL: Record<string, string> = {
  email: 'Email',
  gotify: 'Gotify',
  webhook: 'Webhook',
  'in-app': 'In-app',
}

interface Props {
  enabledRules: Set<string>
  onToggle: (id: string) => void
}

function RuleRow({ rule, enabled, onToggle }: { rule: NotificationRule; enabled: boolean; onToggle: () => void }) {
  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-4 py-2.5 text-sm text-foreground">{rule.event}</td>
      <td className="px-4 py-2.5 text-sm text-muted-foreground">{CHANNEL_LABEL[rule.channel]}</td>
      <td className="px-4 py-2.5 text-sm text-muted-foreground">{rule.target}</td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">
        {rule.lastTriggered ?? <span className="italic">Never</span>}
      </td>
      <td className="px-4 py-2.5">
        <label className="flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            checked={enabled}
            onChange={onToggle}
            className="h-4 w-4 rounded border-input accent-primary"
            aria-label={`${enabled ? 'Disable' : 'Enable'} rule: ${rule.event} via ${rule.channel}`}
          />
          <span className="text-xs text-muted-foreground">{enabled ? 'On' : 'Off'}</span>
        </label>
      </td>
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" aria-label="Edit rule (mock)" className="h-7 w-7">
            <Pencil size={13} aria-hidden="true" />
          </Button>
          <Button variant="ghost" size="icon" aria-label="Delete rule (mock)" className="h-7 w-7 text-destructive hover:text-destructive">
            <Trash2 size={13} aria-hidden="true" />
          </Button>
        </div>
      </td>
    </tr>
  )
}

export default function NotificationRulesTable({ enabledRules, onToggle }: Props) {
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
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Event</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Channel</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Target</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Last triggered</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Enabled</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Actions</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_RULES.map((rule) => (
              <RuleRow
                key={rule.id}
                rule={rule}
                enabled={enabledRules.has(rule.id)}
                onToggle={() => onToggle(rule.id)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </SectionCard>
  )
}
