import { useState, useEffect, useCallback, useRef } from 'react'
import { Loader2, AlertCircle, Plug } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import StatusBanner from '@/components/common/StatusBanner'
import ApiKeyBadge from '@/components/common/ApiKeyBadge'
import { Button } from '@/components/ui/button'
import {
  getAdminProwlarr,
  saveAdminProwlarr,
  testAdminProwlarr,
} from '@/api/prowlarr'
import type { ProwlarrConfigSafe } from '@/api/prowlarr'
import { useI18n } from '@/i18n'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type TestStatus = 'idle' | 'testing' | 'ok' | 'failed'

interface Fields {
  enabled: boolean
  base_url: string
  api_key: string
  label: string
}

function defaultFields(): Fields {
  return { enabled: false, base_url: '', api_key: '', label: '' }
}

function configToFields(c: ProwlarrConfigSafe): Fields {
  return {
    enabled: c.enabled,
    base_url: c.base_url ?? '',
    api_key: '',
    label: c.label ?? '',
  }
}

export default function AdminProwlarr() {
  const { t } = useI18n()
  const [fields, setFields] = useState<Fields>(defaultFields())
  const [hasApiKey, setHasApiKey] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [testMessage, setTestMessage] = useState('')
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await getAdminProwlarr()
      setFields(configToFields(data))
      setHasApiKey(data.has_api_key)
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : t('adminLoadProwlarrFailed'))
    } finally {
      setLoading(false)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

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
      const payload: Parameters<typeof saveAdminProwlarr>[0] = {
        enabled: fields.enabled,
        base_url: fields.base_url.trim(),
        label: fields.label.trim() || undefined,
      }
      if (fields.api_key.trim()) payload.api_key = fields.api_key.trim()
      const updated = await saveAdminProwlarr(payload)
      setFields(configToFields(updated))
      setHasApiKey(updated.has_api_key)
      setDirty(false)
      setSaveStatus('saved')
      setSaveMessage(t('adminProwlarrSaved'))
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
      const result = await testAdminProwlarr()
      if (result.ok) {
        setTestStatus('ok')
        setTestMessage(
          result.version
            ? `${t('adminProwlarrTestOk')} — v${result.version} — ${result.active_indexers ?? 0} indexers`
            : t('adminProwlarrTestOk'),
        )
      } else {
        setTestStatus('failed')
        setTestMessage(result.message ?? t('adminProwlarrTestFailed'))
      }
    } catch (err) {
      setTestStatus('failed')
      setTestMessage(err instanceof Error ? err.message : t('adminProwlarrTestFailed'))
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin" aria-hidden="true" />
        <span className="text-sm">{t('loading')}</span>
      </div>
    )
  }

  if (fetchError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        <div>
          <p className="font-medium">{t('adminLoadProwlarrFailed')}</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
        </div>
      </div>
    )
  }

  const busy = saveStatus === 'saving'
  const testable = !dirty && fields.enabled && fields.base_url.trim() !== '' && (hasApiKey || fields.api_key.trim() !== '')

  return (
    <SectionCard title={t('adminProwlarrTitle')} description={t('adminProwlarrDesc')}>
      <form onSubmit={handleSave} className="flex flex-col gap-6">

        <label className={`flex items-start gap-3 ${busy ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}>
          <input
            type="checkbox"
            checked={fields.enabled}
            disabled={busy}
            onChange={(e) => handleChange('enabled', e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-input accent-primary disabled:opacity-50"
          />
          <div>
            <p className="text-sm font-medium text-foreground">{t('adminProwlarrEnabled')}</p>
            <p className="text-xs text-muted-foreground">{t('adminProwlarrEnabledDesc')}</p>
          </div>
        </label>

        <div>
          <label htmlFor="admin-prowlarr-url" className={LABEL}>{t('adminProwlarrBaseUrl')}</label>
          <input
            id="admin-prowlarr-url"
            type="url"
            value={fields.base_url}
            disabled={busy}
            onChange={(e) => handleChange('base_url', e.target.value)}
            placeholder={t('adminProwlarrBaseUrlPlaceholder')}
            className={INPUT}
          />
        </div>

        <div>
          <label htmlFor="admin-prowlarr-key" className={LABEL}>{t('adminProwlarrApiKey')}</label>
          <input
            id="admin-prowlarr-key"
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

        <div>
          <label htmlFor="admin-prowlarr-label" className={LABEL}>{t('adminProwlarrLabel')}</label>
          <input
            id="admin-prowlarr-label"
            type="text"
            value={fields.label}
            disabled={busy}
            onChange={(e) => handleChange('label', e.target.value)}
            placeholder={t('adminProwlarrLabelPlaceholder')}
            className={INPUT}
          />
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
              {t('adminProwlarrTestConnection')}
            </Button>
          </div>
          {dirty && (
            <p className="text-xs text-muted-foreground">{t('prowlarrSaveBeforeTest')}</p>
          )}
          {!dirty && !testable && fields.enabled && (
            <p className="text-xs text-amber-700 dark:text-amber-400">{t('adminProwlarrNotTestable')}</p>
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
  )
}
