import { useState, useEffect, useRef } from 'react'
import { CheckCircle2, XCircle, Loader2, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { updateIntegrationSettings } from '@/api/integration-settings'
import {
  useIntegrationSettings,
  invalidateIntegrationSettings,
  isProwlarrAvailable,
} from '@/lib/useIntegrationSettings'
import { useAppInfo } from '@/lib/useAppInfo'
import { useI18n } from '@/i18n'

const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

const KNOWN_PAGES = new Set(['dashboard', 'jobs', 'prowlarr'])

export default function AccountHomePageCard() {
  const { t } = useI18n()
  const { settings, loading } = useIntegrationSettings()
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'
  const [homePage, setHomePage] = useState('dashboard')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => { if (successTimer.current) clearTimeout(successTimer.current) }, [])

  useEffect(() => {
    if (!settings) return
    const page = settings.home_page || 'dashboard'
    setHomePage(KNOWN_PAGES.has(page) ? page : 'dashboard')
  }, [settings])

  const prowlarrEnabled = isProwlarrAvailable(settings ?? null)
  const busy = saveStatus === 'saving'

  async function handleSave() {
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      await updateIntegrationSettings({ home_page: homePage })
      invalidateIntegrationSettings()
      setSaveStatus('saved')
      setSaveMessage(t('saved'))
      if (successTimer.current) clearTimeout(successTimer.current)
      successTimer.current = setTimeout(() => setSaveStatus('idle'), 4000)
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : t('saveFailed'))
    }
  }

  if (loading && !settings) return null

  return (
    <SectionCard title={t('sectionNavigation')}>
      <div className="flex flex-col gap-4">
        <div>
          <label htmlFor="account-home-page" className={LABEL}>
            {t('homePageOnLogin')}
          </label>
          <select
            id="account-home-page"
            value={homePage}
            onChange={(e) => setHomePage(e.target.value)}
            disabled={busy}
            className={SELECT}
          >
            <option value="dashboard">{t('navDashboard')}</option>
            <option value="jobs">{t('navJobs')}</option>
            {prowlarrEnabled && <option value="prowlarr">{t('navProwlarr')}</option>}
          </select>
          <p className="mt-1.5 text-xs text-muted-foreground">
            {t('homePageDescPre')} {appName}.
            {!prowlarrEnabled && homePage === 'prowlarr' && (
              <span className="ml-1 text-amber-600 dark:text-amber-400">
                {t('prowlarrFallbackNote')}
              </span>
            )}
          </p>
        </div>

        <div className="flex flex-col gap-3">
          <div>
            <Button size="sm" onClick={handleSave} disabled={busy}>
              {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {t('save')}
            </Button>
          </div>
          {saveStatus === 'saved' && (
            <div className="flex items-center justify-between gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
              <span className="flex items-center gap-2"><CheckCircle2 size={14} aria-hidden="true" /> {saveMessage}</span>
              <button onClick={() => setSaveStatus('idle')} className="shrink-0 opacity-60 hover:opacity-100" aria-label={t('dismiss')}>
                <X size={14} aria-hidden="true" />
              </button>
            </div>
          )}
          {saveStatus === 'error' && (
            <div className="flex items-center justify-between gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <span className="flex items-center gap-2"><XCircle size={14} aria-hidden="true" /> {saveMessage}</span>
              <button onClick={() => setSaveStatus('idle')} className="shrink-0 opacity-60 hover:opacity-100" aria-label={t('dismiss')}>
                <X size={14} aria-hidden="true" />
              </button>
            </div>
          )}
        </div>
      </div>
    </SectionCard>
  )
}
