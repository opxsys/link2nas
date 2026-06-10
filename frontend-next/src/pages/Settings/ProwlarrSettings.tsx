import { useState, useEffect, useCallback, useRef } from 'react'
import { CheckCircle2, Loader2, AlertCircle, Info, Plug } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import StatusBanner from '@/components/common/StatusBanner'
import ApiKeyBadge from '@/components/common/ApiKeyBadge'
import { Button } from '@/components/ui/button'
import {
  getMeProwlarr,
  saveMeProwlarr,
  testMeProwlarr,
} from '@/api/prowlarr'
import type { ProwlarrConfigSafe, ProwlarrMeState } from '@/api/prowlarr'
import { useI18n } from '@/i18n'
import { invalidateProwlarrSearchAvailable } from '@/lib/useProwlarrSearchAvailable'
import ProwlarrQbittorrentGuide from '@/pages/Prowlarr/ProwlarrQbittorrentGuide'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type TestStatus = 'idle' | 'testing' | 'ok' | 'failed'

interface Fields {
  enabled: boolean
  base_url: string
  api_key: string
}

function defaultFields(): Fields {
  return { enabled: false, base_url: '', api_key: '' }
}

function configToFields(c: ProwlarrConfigSafe): Fields {
  return { enabled: c.enabled, base_url: c.base_url ?? '', api_key: '' }
}

export default function ProwlarrSettings() {
  const { t } = useI18n()
  const [fields, setFields] = useState<Fields>(defaultFields())
  const [hasApiKey, setHasApiKey] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [meState, setMeState] = useState<ProwlarrMeState | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [testMessage, setTestMessage] = useState('')
  const [activeTab, setActiveTab] = useState<'search' | 'send'>('search')
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await getMeProwlarr()
      setMeState(data)
      if (data.user_config) {
        setFields(configToFields(data.user_config))
        setHasApiKey(data.user_config.has_api_key)
      }
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : t('prowlarrApiLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])
  useEffect(() => () => { if (saveTimer.current) clearTimeout(saveTimer.current) }, [])

  function handleChange<K extends keyof Fields>(key: K, value: Fields[K]) {
    setFields((prev) => ({ ...prev, [key]: value }))
    setDirty(true)
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
    if (testStatus !== 'idle') { setTestStatus('idle'); setTestMessage('') }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    if (saveTimer.current) clearTimeout(saveTimer.current)
    setSaveStatus('saving')
    setSaveMessage('')
    setTestStatus('idle')
    setTestMessage('')
    try {
      const payload: Parameters<typeof saveMeProwlarr>[0] = {
        enabled: fields.enabled,
        base_url: fields.base_url.trim(),
      }
      if (fields.api_key.trim()) payload.api_key = fields.api_key.trim()
      const updated = await saveMeProwlarr(payload)
      setFields(configToFields(updated))
      setHasApiKey(updated.has_api_key)
      setDirty(false)
      getMeProwlarr().then(setMeState).catch(() => {})
      invalidateProwlarrSearchAvailable()
      setSaveStatus('saved')
      setSaveMessage(t('prowlarrApiSaved'))
      saveTimer.current = setTimeout(() => setSaveStatus('idle'), 4000)
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : t('saveFailed'))
    }
  }

  async function handleTest() {
    setSaveStatus('idle')
    setSaveMessage('')
    setTestStatus('testing')
    setTestMessage('')
    try {
      const result = await testMeProwlarr()
      if (result.ok) {
        setTestStatus('ok')
        setTestMessage(
          result.version
            ? `${t('prowlarrApiTestOk')} — v${result.version} — ${result.active_indexers ?? 0} indexers`
            : t('prowlarrApiTestOk'),
        )
      } else {
        setTestStatus('failed')
        setTestMessage(result.message ?? t('prowlarrApiTestFailed'))
      }
    } catch (err) {
      setTestStatus('failed')
      setTestMessage(err instanceof Error ? err.message : t('prowlarrApiTestFailed'))
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-8 text-muted-foreground">
        <Loader2 size={18} className="animate-spin" aria-hidden="true" />
        <span className="text-sm">{t('loading')}</span>
      </div>
    )
  }

  if (fetchError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        <div>
          <p className="font-medium">{t('prowlarrApiLoadFailed')}</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
        </div>
      </div>
    )
  }

  const busy = saveStatus === 'saving'
  const testable = !dirty && (meState?.search_available || (fields.enabled && fields.base_url.trim() !== '' && (hasApiKey || fields.api_key.trim() !== '')))

  return (
    <div className="flex flex-col gap-6">
      {/* Tab bar */}
      <div role="tablist" className="flex border-b border-border -mb-2">
        {(['search', 'send'] as const).map((tab) => (
          <button
            key={tab}
            role="tab"
            aria-selected={activeTab === tab}
            onClick={() => setActiveTab(tab)}
            className={[
              'px-4 py-2.5 text-sm font-medium -mb-px border-b-2 transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-t-sm',
              activeTab === tab
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            ].join(' ')}
          >
            {tab === 'search' ? t('prowlarrTabSearch') : t('prowlarrTabSend')}
          </button>
        ))}
      </div>

      {activeTab === 'search' && (
        <>
          <EffectiveSourceBadge meState={meState} />

          <SectionCard title={t('prowlarrApiTitle')} description={t('prowlarrApiDesc')}>
            <form onSubmit={handleSave} className="flex flex-col gap-5">

              <label className={`flex items-start gap-3 ${busy ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}>
                <input
                  type="checkbox"
                  checked={fields.enabled}
                  disabled={busy}
                  onChange={(e) => handleChange('enabled', e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-input accent-primary disabled:opacity-50"
                />
                <div>
                  <p className="text-sm font-medium text-foreground">{t('prowlarrApiEnabled')}</p>
                  <p className="text-xs text-muted-foreground">{t('prowlarrApiEnabledDesc')}</p>
                </div>
              </label>

              <div>
                <label htmlFor="prowlarr-api-url" className={LABEL}>{t('prowlarrApiBaseUrl')}</label>
                <input
                  id="prowlarr-api-url"
                  type="url"
                  value={fields.base_url}
                  disabled={busy}
                  onChange={(e) => handleChange('base_url', e.target.value)}
                  placeholder="http://nas.local:9696"
                  className={INPUT}
                />
              </div>

              <div>
                <label htmlFor="prowlarr-api-key" className={LABEL}>{t('prowlarrApiApiKey')}</label>
                <input
                  id="prowlarr-api-key"
                  type="password"
                  value={fields.api_key}
                  disabled={busy}
                  onChange={(e) => handleChange('api_key', e.target.value)}
                  placeholder={hasApiKey ? t('adminProwlarrApiKeyPlaceholder') : t('adminProwlarrApiKeyPlaceholderNew')}
                  autoComplete="new-password"
                  className={INPUT}
                />
                <div className="mt-1.5 flex items-center gap-2">
                  <ApiKeyBadge hasKey={hasApiKey} />
                  <span className="text-xs text-muted-foreground">{t('adminProwlarrApiKeyHint')}</span>
                </div>
              </div>

              <div className="flex flex-col gap-2">
                <div className="flex flex-wrap items-center gap-3">
                  <Button type="submit" size="sm" disabled={busy}>
                    {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
                    {t('saveChanges')}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={!testable || busy || testStatus === 'testing'}
                    onClick={handleTest}
                  >
                    {testStatus === 'testing'
                      ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                      : <Plug size={13} className="mr-1.5" aria-hidden="true" />}
                    {t('prowlarrApiTestConnection')}
                  </Button>
                </div>
                {dirty && (
                  <p className="text-xs text-muted-foreground">{t('prowlarrSaveBeforeTest')}</p>
                )}
              </div>

              {saveStatus === 'saved' && (
                <StatusBanner color="green" message={saveMessage} onDismiss={() => { if (saveTimer.current) clearTimeout(saveTimer.current); setSaveStatus('idle') }} />
              )}
              {saveStatus === 'error' && (
                <StatusBanner color="red" message={saveMessage} onDismiss={() => setSaveStatus('idle')} />
              )}
              {testStatus === 'ok' && (
                <StatusBanner color="green" message={testMessage} onDismiss={() => setTestStatus('idle')} />
              )}
              {testStatus === 'failed' && (
                <StatusBanner color="red" message={testMessage} onDismiss={() => setTestStatus('idle')} />
              )}
            </form>
          </SectionCard>
        </>
      )}

      {activeTab === 'send' && <ProwlarrQbittorrentGuide />}
    </div>
  )
}

function EffectiveSourceBadge({ meState }: { meState: ProwlarrMeState | null }) {
  const { t } = useI18n()
  if (!meState) return null

  const source = meState.effective_config_source
  const available = meState.search_available

  if (source === 'none' || !available) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
        <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
        <span>{t('prowlarrApiSourceNone')}</span>
      </div>
    )
  }

  if (source === 'global') {
    return (
      <div className="flex items-start gap-2 rounded-md border border-blue-200 bg-blue-50 p-3 text-xs text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400">
        <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
        <span>{t('prowlarrApiSourceGlobal')}</span>
      </div>
    )
  }

  return (
    <div className="flex items-start gap-2 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
      <CheckCircle2 size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
      <span>{t('prowlarrApiSourceUser')}</span>
    </div>
  )
}
