import { useState, useEffect } from 'react'
import { CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { updateIntegrationSettings } from '@/api/integration-settings'
import {
  useIntegrationSettings,
  invalidateIntegrationSettings,
  isProwlarrAvailable,
} from '@/lib/useIntegrationSettings'

const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

const KNOWN_PAGES = new Set(['dashboard', 'jobs', 'prowlarr'])

export default function AccountHomePageCard() {
  const { settings, loading } = useIntegrationSettings()
  const [homePage, setHomePage] = useState('dashboard')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')

  useEffect(() => {
    if (!settings) return
    const page = settings.home_page || 'dashboard'
    // Fallback unknown or legacy values (e.g. control-center) to dashboard
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
      setSaveMessage('Saved.')
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : 'Save failed.')
    }
  }

  if (loading && !settings) return null

  return (
    <SectionCard title="Navigation">
      <div className="flex flex-col gap-4">
        <div>
          <label htmlFor="account-home-page" className={LABEL}>
            Home page on login
          </label>
          <select
            id="account-home-page"
            value={homePage}
            onChange={(e) => setHomePage(e.target.value)}
            disabled={busy}
            className={SELECT}
          >
            <option value="dashboard">Dashboard</option>
            <option value="jobs">Jobs</option>
            {prowlarrEnabled && <option value="prowlarr">Prowlarr</option>}
          </select>
          <p className="mt-1.5 text-xs text-muted-foreground">
            Page shown when you open Link2NAS.
            {!prowlarrEnabled && homePage === 'prowlarr' && (
              <span className="ml-1 text-amber-600 dark:text-amber-400">
                Prowlarr is disabled — will fall back to Dashboard.
              </span>
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button size="sm" onClick={handleSave} disabled={busy}>
            {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            Save
          </Button>
          {saveStatus === 'saved' && (
            <span className="flex items-center gap-1.5 text-sm text-green-700 dark:text-green-400">
              <CheckCircle2 size={14} aria-hidden="true" /> {saveMessage}
            </span>
          )}
          {saveStatus === 'error' && (
            <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
              <XCircle size={14} aria-hidden="true" /> {saveMessage}
            </span>
          )}
        </div>
      </div>
    </SectionCard>
  )
}
