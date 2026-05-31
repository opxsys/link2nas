import { useState, useEffect } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getRestartCooldowns, saveRestartCooldowns } from '@/api/admin-settings'
import type { RestartCooldowns } from './admin.types'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

const INPUT = 'w-28 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'text-sm font-medium text-foreground'
const HINT = 'text-xs text-muted-foreground'

const FIELDS: { key: keyof RestartCooldowns; label: string; hint: string }[] = [
  {
    key: 'default_seconds',
    label: 'Default cooldown',
    hint: 'Applied when no provider-specific value is set.',
  },
  {
    key: 'realdebrid_seconds',
    label: 'Real-Debrid cooldown',
    hint: 'Cooldown before retrying a Real-Debrid restart.',
  },
  {
    key: 'alldebrid_seconds',
    label: 'AllDebrid cooldown',
    hint: 'Cooldown before retrying an AllDebrid restart.',
  },
]

export default function AdminTimeouts() {
  const [values, setValues] = useState<RestartCooldowns>({
    default_seconds: 10,
    realdebrid_seconds: 60,
    alldebrid_seconds: 8,
  })
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')

  async function load() {
    setLoading(true)
    setFetchError(null)
    try {
      setValues(await getRestartCooldowns())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load timeout settings.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  function handleChange(key: keyof RestartCooldowns, raw: string) {
    const parsed = parseInt(raw, 10)
    setValues((prev) => ({ ...prev, [key]: Number.isFinite(parsed) ? parsed : 0 }))
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      const updated = await saveRestartCooldowns(values)
      setValues(updated)
      setSaveStatus('saved')
      setSaveMessage('Timeout settings saved.')
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : 'Save failed.')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin" aria-hidden="true" />
        <span className="ml-2 text-sm">Loading…</span>
      </div>
    )
  }

  if (fetchError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        <div>
          <p className="font-medium">Failed to load timeout settings</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
        </div>
      </div>
    )
  }

  return (
    <SectionCard
      title="Restart Cooldowns"
      description="Minimum wait time before a provider job can be restarted. Values are in seconds (0–3600)."
    >
      <form onSubmit={handleSubmit} className="flex flex-col gap-6">
        <div className="grid gap-4 sm:grid-cols-3">
          {FIELDS.map(({ key, label, hint }) => (
            <div key={key} className="flex flex-col gap-1.5">
              <label htmlFor={`timeout-${key}`} className={LABEL}>{label}</label>
              <div className="flex items-center gap-2">
                <input
                  id={`timeout-${key}`}
                  type="number"
                  min={0}
                  max={3600}
                  required
                  value={values[key]}
                  onChange={(e) => handleChange(key, e.target.value)}
                  className={INPUT}
                />
                <span className="text-sm text-muted-foreground">s</span>
              </div>
              <p className={HINT}>{hint}</p>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" size="sm" disabled={saveStatus === 'saving'}>
            {saveStatus === 'saving' && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            Save changes
          </Button>

          {saveStatus === 'saved' && (
            <span className="flex items-center gap-1.5 text-sm text-green-700 dark:text-green-400">
              <CheckCircle2 size={14} aria-hidden="true" />{saveMessage}
            </span>
          )}
          {saveStatus === 'error' && (
            <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
              <XCircle size={14} aria-hidden="true" />{saveMessage}
            </span>
          )}
        </div>
      </form>
    </SectionCard>
  )
}
