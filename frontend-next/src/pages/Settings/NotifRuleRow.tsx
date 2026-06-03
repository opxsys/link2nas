import { useState } from 'react'
import { Bell, Pencil, Trash2, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { updateNotificationRule } from '@/api/notifications'
import type { NotificationConfig, NotificationRule } from '@/pages/Notifications/notifications.types'

const SEV_CLASS: Record<string, string> = {
  info:     'border-border bg-muted text-muted-foreground',
  warning:  'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400',
  error:    'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400',
  critical: 'border-red-300 bg-red-100 text-red-800 dark:border-red-700 dark:bg-red-900 dark:text-red-300',
}
const BADGE = 'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium capitalize'

interface Props {
  rule: NotificationRule
  configs: NotificationConfig[]
  emailBlocked: boolean
  onEdit: () => void
  onDelete: () => void
  onToggled: (updated: NotificationRule) => void
}

export default function NotifRuleRow({ rule, configs, emailBlocked, onEdit, onDelete, onToggled }: Props) {
  const [toggling, setToggling] = useState(false)
  const cfg = configs.find(c => c.id === rule.config_id)
  const isEmailRule = cfg?.channel === 'email'
  const blocked = isEmailRule && emailBlocked

  async function handleToggle() {
    const next = !rule.is_enabled
    setToggling(true)
    try {
      const updated = await updateNotificationRule(rule.id, { is_enabled: next })
      onToggled(updated)
    } catch {
      // revert: parent state unchanged, toggle reverts on re-render
    } finally {
      setToggling(false)
    }
  }

  return (
    <div className={`flex items-center gap-3 rounded-lg border border-border p-3 ${blocked ? 'opacity-60' : ''}`}>
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted">
        <Bell size={14} aria-hidden="true" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm font-medium text-foreground">{rule.name}</span>
          <span className={`${BADGE} ${SEV_CLASS[rule.severity_min] ?? SEV_CLASS.info}`}>
            {rule.severity_min}+
          </span>
          {cfg && <span className="text-xs text-muted-foreground">{cfg.name}</span>}
        </div>
        {rule.event_types.length > 0 ? (
          <p className="mt-0.5 truncate text-xs text-muted-foreground">
            Events: {rule.event_types.join(', ')}
          </p>
        ) : (
          <p className="mt-0.5 text-xs text-muted-foreground">All events</p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <label className={`flex items-center gap-1.5 ${blocked ? 'cursor-not-allowed' : 'cursor-pointer'}`}>
          <span className="text-xs text-muted-foreground">{rule.is_enabled ? 'On' : 'Off'}</span>
          {toggling
            ? <Loader2 size={13} className="animate-spin text-muted-foreground" aria-hidden="true" />
            : (
              <input
                type="checkbox"
                checked={rule.is_enabled}
                disabled={blocked}
                onChange={handleToggle}
                className="h-4 w-4 rounded border-input accent-primary disabled:opacity-50"
                aria-label={`${rule.is_enabled ? 'Disable' : 'Enable'} ${rule.name}`}
              />
            )
          }
        </label>
        <Button variant="ghost" size="icon" className="h-7 w-7" aria-label={`Edit ${rule.name}`} onClick={onEdit}>
          <Pencil size={13} aria-hidden="true" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" aria-label={`Delete ${rule.name}`} onClick={onDelete}>
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
