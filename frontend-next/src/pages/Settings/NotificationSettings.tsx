import { useState } from 'react'
import { Bell, Plus } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { MOCK_NOTIFICATION_RULES } from './settings.mock'

export default function NotificationSettings() {
  const [rules, setRules] = useState(MOCK_NOTIFICATION_RULES)

  function toggleRule(id: string) {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
    )
  }

  return (
    <SectionCard
      title="Notification Rules"
      description="Configure when and how you receive notifications."
      actions={
        <Button variant="outline" size="sm" disabled>
          <Plus size={13} aria-hidden="true" /> Add rule
        </Button>
      }
    >
      <div className="flex flex-col gap-3">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className="flex items-center gap-4 rounded-lg border border-border p-4"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-foreground">
              <Bell size={16} aria-hidden="true" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-foreground">{rule.event}</p>
              <p className="text-xs text-muted-foreground">Channel: {rule.channel}</p>
            </div>
            <label className="flex cursor-pointer items-center gap-2">
              <span className="text-xs text-muted-foreground">
                {rule.enabled ? 'Enabled' : 'Disabled'}
              </span>
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={() => toggleRule(rule.id)}
                className="h-4 w-4 rounded border-input accent-primary"
                aria-label={`${rule.event} notification`}
              />
            </label>
          </div>
        ))}
        <p className="text-xs text-muted-foreground">
          Toggle state is local only — not persisted.
        </p>
      </div>
    </SectionCard>
  )
}
