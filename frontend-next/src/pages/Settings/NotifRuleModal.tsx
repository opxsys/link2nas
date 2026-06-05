import { useState, useId } from 'react'
import { X, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { createNotificationRule, updateNotificationRule } from '@/api/notifications'
import { ApiError } from '@/api/client'
import type { NotificationConfig, NotificationRule } from '@/pages/Notifications/notifications.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

// Canonical event types emitted by the backend
const KNOWN_EVENT_TYPES = [
  'job.created', 'job.started', 'job.ready', 'job.links_ready',
  'job.completed', 'job.cancelled',
  'provider.failed', 'destination.failed',
]

const SEVERITIES = ['info', 'warning', 'error', 'critical']

interface Props {
  editing: NotificationRule | null
  configs: NotificationConfig[]
  onClose: () => void
  onSaved: (rule: NotificationRule) => void
}

export default function NotifRuleModal({ editing, configs, onClose, onSaved }: Props) {
  const isEdit = editing !== null
  const uid = useId()

  const [name, setName] = useState(editing?.name ?? '')
  const [configId, setConfigId] = useState(editing?.config_id ?? configs[0]?.id ?? '')
  const [severityMin, setSeverityMin] = useState<string>(editing?.severity_min ?? 'info')
  const [selectedTypes, setSelectedTypes] = useState<string[]>(editing?.event_types ?? [])
  const [rateLimit, setRateLimit] = useState(String(editing?.rate_limit_per_hour ?? 30))
  const [isEnabled, setIsEnabled] = useState(editing?.is_enabled ?? true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function toggleType(t: string) {
    setSelectedTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const rate = parseInt(rateLimit, 10)
    if (isNaN(rate) || rate < 0 || rate > 1000) {
      setError('Rate limit must be between 0 and 1000.')
      return
    }
    if (!configId) {
      setError('Select a channel.')
      return
    }
    setSaving(true)
    setError(null)
    const payload = {
      name, config_id: configId, severity_min: severityMin,
      event_types: selectedTypes, rate_limit_per_hour: rate, is_enabled: isEnabled,
    }
    try {
      const saved = isEdit
        ? await updateNotificationRule(editing.id, payload)
        : await createNotificationRule(payload)
      onSaved(saved)
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4 pt-16"
      role="dialog" aria-modal="true"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-md rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{isEdit ? 'Edit rule' : 'Add rule'}</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label="Close">
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-5">
          <div>
            <label htmlFor={`${uid}-name`} className={LABEL}>Name <span className="text-destructive">*</span></label>
            <input id={`${uid}-name`} type="text" className={INPUT} value={name} required
              onChange={e => setName(e.target.value)} disabled={saving} />
          </div>

          <div>
            <label htmlFor={`${uid}-cfg`} className={LABEL}>Channel <span className="text-destructive">*</span></label>
            <select id={`${uid}-cfg`} className={INPUT} value={configId}
              onChange={e => setConfigId(e.target.value)} disabled={saving || configs.length === 0}>
              {configs.length === 0
                ? <option value="">No channels — add one first</option>
                : configs.map(c => (
                  <option key={c.id} value={c.id}>{c.name} ({c.channel})</option>
                ))}
            </select>
          </div>

          <div>
            <label htmlFor={`${uid}-sev`} className={LABEL}>Minimum severity</label>
            <select id={`${uid}-sev`} className={INPUT} value={severityMin}
              onChange={e => setSeverityMin(e.target.value)} disabled={saving}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          <div>
            <p className={`${LABEL} mb-2`}>
              Event types
              <span className="ml-1 font-normal text-muted-foreground">(none selected = all events)</span>
            </p>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
              {KNOWN_EVENT_TYPES.map(t => (
                <label key={t} className="flex items-center gap-1.5 text-xs text-foreground">
                  <input type="checkbox" checked={selectedTypes.includes(t)}
                    onChange={() => toggleType(t)} disabled={saving}
                    className="h-3.5 w-3.5 rounded border-input accent-primary" />
                  {t}
                </label>
              ))}
            </div>
          </div>

          <div>
            <label htmlFor={`${uid}-rate`} className={LABEL}>Rate limit per hour <span className="text-muted-foreground">(0 = unlimited)</span></label>
            <input id={`${uid}-rate`} type="number" min={0} max={1000} className={INPUT}
              value={rateLimit} onChange={e => setRateLimit(e.target.value)} disabled={saving} />
          </div>

          <label className="flex items-center gap-2 text-sm text-foreground">
            <input type="checkbox" checked={isEnabled} onChange={e => setIsEnabled(e.target.checked)}
              disabled={saving} className="h-4 w-4 rounded border-input accent-primary" />
            Enabled
          </label>

          {error && (
            <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>Cancel</Button>
            <Button type="submit" size="sm" disabled={saving || configs.length === 0}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {isEdit ? 'Save changes' : 'Add rule'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
