import { useState, useEffect } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getGeneralSettings, saveGeneralSettings } from '@/api/admin-settings'
import type { GeneralSettings } from './admin.types'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

export default function AdminGeneral() {
  const [settings, setSettings] = useState<GeneralSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)

  const [appName, setAppName] = useState('')
  const [appTagline, setAppTagline] = useState('')
  const [publicBaseUrl, setPublicBaseUrl] = useState('')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')

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
      setSaveMessage('Settings saved.')
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
          <p className="font-medium">Failed to load general settings</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
        </div>
      </div>
    )
  }

  return (
    <SectionCard title="General" description="Application name, tagline, and public URL.">
      <form onSubmit={handleSubmit} className="flex flex-col gap-5">
        <div>
          <label htmlFor="general-app-name" className={LABEL}>App name</label>
          <input
            id="general-app-name"
            type="text"
            value={appName}
            onChange={(e) => setAppName(e.target.value)}
            placeholder="Link2NAS"
            className={INPUT}
          />
        </div>

        <div>
          <label htmlFor="general-app-tagline" className={LABEL}>Tagline</label>
          <input
            id="general-app-tagline"
            type="text"
            value={appTagline}
            onChange={(e) => setAppTagline(e.target.value)}
            placeholder="Self-hosted download manager"
            className={INPUT}
          />
        </div>

        <div>
          <label htmlFor="general-public-url" className={LABEL}>Public base URL</label>
          <input
            id="general-public-url"
            type="url"
            value={publicBaseUrl}
            onChange={(e) => setPublicBaseUrl(e.target.value)}
            placeholder="https://link2nas.example.com"
            className={INPUT}
          />
          <p className="mt-1 text-xs text-muted-foreground">
            Used for invitation links and email URLs. Leave blank to use the request origin.
          </p>
          {settings?.effective_public_base_url && (
            <p className="mt-1 text-xs text-muted-foreground">
              Effective URL: <span className="font-mono">{settings.effective_public_base_url}</span>
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" size="sm" disabled={saveStatus === 'saving'}>
            {saveStatus === 'saving' && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            Save changes
          </Button>

          {saveStatus === 'saved' && (
            <span className="flex items-center gap-1.5 text-sm text-green-700 dark:text-green-400">
              <CheckCircle2 size={14} aria-hidden="true" />
              {saveMessage}
            </span>
          )}
          {saveStatus === 'error' && (
            <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
              <XCircle size={14} aria-hidden="true" />
              {saveMessage}
            </span>
          )}
        </div>
      </form>
    </SectionCard>
  )
}
