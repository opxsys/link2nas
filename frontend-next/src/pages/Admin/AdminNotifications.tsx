import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, CheckCircle2, Loader2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import {
  getAdminNotificationSettings,
  saveAdminNotificationSettings,
} from '@/api/admin-notification-settings'
import { useI18n } from '@/i18n'

const DEFAULT_MAX_AGE_HOURS = 24
const INPUT = 'h-9 w-24 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

export default function AdminNotifications() {
  const { t } = useI18n()
  const [maxAgeHours, setMaxAgeHours] = useState(DEFAULT_MAX_AGE_HOURS)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const settings = await getAdminNotificationSettings()
      setMaxAgeHours(settings.event_policy.max_age_hours)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('adminNotificationsLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  async function save(event: React.FormEvent) {
    event.preventDefault()
    setSaving(true)
    setSaved(false)
    setError(null)
    try {
      const settings = await saveAdminNotificationSettings({
        event_policy: { max_age_hours: maxAgeHours },
      })
      setMaxAgeHours(settings.event_policy.max_age_hours)
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <div className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 size={16} className="animate-spin" />{t('loading')}</div>
  }

  return (
    <SectionCard title={t('adminNotificationsTitle')} description={t('adminNotificationsDesc')}>
      <form onSubmit={save} className="flex flex-col gap-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <label htmlFor="notification-event-max-age" className="text-sm font-medium text-foreground">
              {t('adminNotificationMaxAge')}
            </label>
            <p className="mt-1 max-w-2xl text-xs text-muted-foreground">{t('adminNotificationMaxAgeHelp')}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <input
              id="notification-event-max-age"
              type="number"
              min={1}
              max={720}
              required
              value={maxAgeHours}
              disabled={saving}
              className={INPUT}
              onChange={(event) => { setMaxAgeHours(Number(event.target.value)); setSaved(false) }}
            />
            <span className="text-xs text-muted-foreground">{t('unitHours')}</span>
          </div>
        </div>
        <div><Button type="submit" size="sm" disabled={saving || maxAgeHours < 1 || maxAgeHours > 720}>{saving && <Loader2 size={13} className="mr-1.5 animate-spin" />}{t('adminSaveSettings')}</Button></div>
        {saved && <div className="flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-400"><CheckCircle2 size={15} />{t('adminNotificationsSaved')}</div>}
        {error && <div className="flex items-center gap-2 text-sm text-red-700 dark:text-red-400"><AlertCircle size={15} />{error}</div>}
      </form>
    </SectionCard>
  )
}
