import { useState, useEffect, useRef } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getGeneralSettings, saveGeneralSettings } from '@/api/admin-settings'
import type { GeneralSettings } from './admin.types'
import { useI18n } from '@/i18n'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

export default function AdminGeneral() {
  const { t } = useI18n()
  const [settings, setSettings] = useState<GeneralSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)

  const [appName, setAppName] = useState('')
  const [appTagline, setAppTagline] = useState('')
  const [publicBaseUrl, setPublicBaseUrl] = useState('')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const busy = saveStatus === 'saving'

  function clearFeedback() {
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
  }

  async function load() {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await getGeneralSettings()
      setSettings(data)
      setAppName(data.app_name)
      setAppTagline(data.app_tagline)
      setPublicBaseUrl(data.public_base_url)
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load settings.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (successTimer.current) clearTimeout(successTimer.current)
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      const updated = await saveGeneralSettings({
        app_name: appName.trim(),
        app_tagline: appTagline.trim(),
        public_base_url: publicBaseUrl.trim(),
      })
      setSettings(updated)
      setAppName(updated.app_name)
      setAppTagline(updated.app_tagline)
      setPublicBaseUrl(updated.public_base_url)
      setSaveStatus('saved')
      setSaveMessage(t('adminSettingsSaved'))
      successTimer.current = setTimeout(() => { setSaveStatus('idle'); setSaveMessage('') }, 4000)
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
          <p className="font-medium">{t('adminLoadGeneralFailed')}</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
        </div>
      </div>
    )
  }

  return (
    <SectionCard title={t('adminGeneralTitle')} description={t('adminGeneralDesc')}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-5">
        <div>
          <label htmlFor="general-app-name" className={LABEL}>{t('adminAppNameLabel')}</label>
          <input
            id="general-app-name"
            type="text"
            value={appName}
            onChange={(e) => { clearFeedback(); setAppName(e.target.value) }}
            placeholder="Link2NAS"
            disabled={busy}
            className={INPUT}
          />
        </div>

        <div>
          <label htmlFor="general-app-tagline" className={LABEL}>{t('adminTaglineLabel')}</label>
          <input
            id="general-app-tagline"
            type="text"
            value={appTagline}
            onChange={(e) => { clearFeedback(); setAppTagline(e.target.value) }}
            placeholder={t('adminTaglinePlaceholder')}
            disabled={busy}
            className={INPUT}
          />
        </div>

        <div>
          <label htmlFor="general-public-url" className={LABEL}>{t('adminPublicBaseUrlLabel')}</label>
          <input
            id="general-public-url"
            type="url"
            value={publicBaseUrl}
            onChange={(e) => { clearFeedback(); setPublicBaseUrl(e.target.value) }}
            placeholder="https://link2nas.example.com"
            disabled={busy}
            className={INPUT}
          />
          <p className="mt-1 text-xs text-muted-foreground">{t('adminPublicBaseUrlHint')}</p>
          {settings?.effective_public_base_url && (
            <p className="mt-1 text-xs text-muted-foreground">
              {t('adminEffectiveUrl')} <span className="font-mono">{settings.effective_public_base_url}</span>
            </p>
          )}
        </div>

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
              onClick={() => { if (successTimer.current) clearTimeout(successTimer.current); setSaveStatus('idle'); setSaveMessage('') }}
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
              onClick={() => { setSaveStatus('idle'); setSaveMessage('') }}
              className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              aria-label={t('dismiss')}
            >
              <X size={13} aria-hidden="true" />
            </button>
          </div>
        )}
      </form>
    </SectionCard>
  )
}
