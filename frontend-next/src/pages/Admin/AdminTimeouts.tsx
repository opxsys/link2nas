import { useState, useEffect, useCallback, useRef } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getRestartCooldowns, saveRestartCooldowns } from '@/api/admin-settings'
import type { RestartCooldowns } from './admin.types'
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

const INPUT = 'w-28 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'text-sm font-medium text-foreground'
const HINT = 'text-xs text-muted-foreground'

export default function AdminTimeouts() {
  const { t } = useI18n()

  const FIELDS: { key: keyof RestartCooldowns; labelKey: TranslationKey; hintKey: TranslationKey }[] = [
    { key: 'default_seconds',    labelKey: 'adminDefaultCooldown', hintKey: 'adminDefaultCooldownHint' },
    { key: 'realdebrid_seconds', labelKey: 'adminRdCooldown',      hintKey: 'adminRdCooldownHint'      },
    { key: 'alldebrid_seconds',  labelKey: 'adminAdCooldown',      hintKey: 'adminAdCooldownHint'      },
  ]
  const [values, setValues] = useState<RestartCooldowns>({
    default_seconds: 10,
    realdebrid_seconds: 60,
    alldebrid_seconds: 8,
  })
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const busy = saveStatus === 'saving'

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      setValues(await getRestartCooldowns())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load timeout settings.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    return () => {
      if (saveTimer.current) clearTimeout(saveTimer.current)
    }
  }, [])

  function clearFeedback() {
    if (saveStatus !== 'idle') {
      setSaveStatus('idle')
      setSaveMessage('')
    }
  }

  function handleChange(key: keyof RestartCooldowns, raw: string) {
    const parsed = parseInt(raw, 10)
    setValues((prev) => ({ ...prev, [key]: Number.isFinite(parsed) ? parsed : 0 }))
    clearFeedback()
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    if (saveTimer.current) clearTimeout(saveTimer.current)

    setSaveStatus('saving')
    setSaveMessage('')

    try {
      const updated = await saveRestartCooldowns(values)
      setValues(updated)
      setSaveStatus('saved')
      setSaveMessage(t('adminTimeoutsSaved'))
      saveTimer.current = setTimeout(() => {
        setSaveStatus('idle')
        setSaveMessage('')
      }, 4000)
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : 'Save failed.')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin" aria-hidden="true" />
        <span className="ml-2 text-sm">{t('loading')}</span>
      </div>
    )
  }

  if (fetchError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        <div>
          <p className="font-medium">{t('adminLoadTimeoutsFailed')}</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
        </div>
      </div>
    )
  }

  return (
    <SectionCard
      title={t('adminTimeoutsTitle')}
      description={t('adminTimeoutsDesc')}
    >
      <form onSubmit={handleSubmit} className="flex flex-col gap-6">
        <div className="grid gap-4 sm:grid-cols-3">
          {FIELDS.map(({ key, labelKey, hintKey }) => (
            <div key={key} className="flex flex-col gap-1.5">
              <label htmlFor={`timeout-${key}`} className={LABEL}>{t(labelKey)}</label>
              <div className="flex items-center gap-2">
                <input
                  id={`timeout-${key}`}
                  type="number"
                  min={0}
                  max={3600}
                  required
                  value={values[key]}
                  onChange={(e) => handleChange(key, e.target.value)}
                  disabled={busy}
                  className={INPUT}
                />
                <span className="text-sm text-muted-foreground">s</span>
              </div>
              <p className={HINT}>{t(hintKey)}</p>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-3">
          <div>
            <Button type="submit" size="sm" disabled={busy}>
              {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {t('saveChanges')}
            </Button>
          </div>

          {saveStatus === 'saved' && (
            <div className="flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
              <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{saveMessage}</span>
              <button
                type="button"
                onClick={() => {
                  if (saveTimer.current) clearTimeout(saveTimer.current)
                  setSaveStatus('idle')
                  setSaveMessage('')
                }}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}

          {saveStatus === 'error' && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <XCircle size={15} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{saveMessage}</span>
              <button
                type="button"
                onClick={() => {
                  setSaveStatus('idle')
                  setSaveMessage('')
                }}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
        </div>
      </form>
    </SectionCard>
  )
}
