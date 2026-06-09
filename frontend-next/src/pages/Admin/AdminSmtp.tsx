import { useState, useEffect, useCallback, useRef } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle, Send, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getSmtpSettings, saveSmtpSettings, testSmtpSettings } from '@/api/admin-smtp'
import { invalidateSmtpStatus } from '@/lib/useSmtpStatus'
import { invalidateMe } from '@/lib/useMe'
import type { RealSmtpSettings } from './admin.types'
import AdminSmtpFields, { type SmtpFields } from './AdminSmtpFields'
import { useI18n } from '@/i18n'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type TestStatus = 'idle' | 'sending' | 'sent' | 'failed'

function settingsToFields(s: RealSmtpSettings): SmtpFields {
  return {
    enabled: s.enabled,
    host: s.host,
    port: s.port,
    username: s.username,
    password: '',
    fromEmail: s.from_email,
    fromName: s.from_name,
    useTls: s.use_tls,
    useSsl: s.use_ssl,
    hasPassword: s.has_password,
  }
}

export default function AdminSmtp() {
  const { t } = useI18n()
  const [fields, setFields] = useState<SmtpFields>({
    enabled: false, host: '', port: 587, username: '', password: '',
    fromEmail: '', fromName: '', useTls: true, useSsl: false, hasPassword: false,
  })

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
      const data = await getSmtpSettings()
      setFields(settingsToFields(data))
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : t('adminLoadSmtpFailed'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function handleChange<K extends keyof SmtpFields>(key: K, value: SmtpFields[K]) {
    setFields((prev) => ({ ...prev, [key]: value }))
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
      const updated = await saveSmtpSettings({
        enabled: fields.enabled,
        host: fields.host.trim(),
        port: fields.port,
        username: fields.username.trim(),
        password: fields.password,
        from_email: fields.fromEmail.trim(),
        from_name: fields.fromName.trim(),
        use_tls: fields.useTls,
        use_ssl: fields.useSsl,
      })
      setFields(settingsToFields(updated))
      setSaveStatus('saved')
      setSaveMessage(t('adminSmtpSaved'))
      invalidateSmtpStatus()
      invalidateMe()
      saveTimer.current = setTimeout(() => setSaveStatus('idle'), 4000)
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : t('saveFailed'))
    }
  }

  async function handleTest() {
    setSaveStatus('idle')
    setSaveMessage('')
    setTestStatus('sending')
    setTestMessage('')
    try {
      const result = await testSmtpSettings()
      if (result.ok) {
        setTestStatus('sent')
        setTestMessage(result.message ?? t('smtpTestEmailSent'))
      } else {
        setTestStatus('failed')
        setTestMessage(result.error ?? t('testFailed'))
      }
    } catch (err) {
      setTestStatus('failed')
      setTestMessage(err instanceof Error ? err.message : t('testFailed'))
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
          <p className="font-medium">{t('adminLoadSmtpFailed')}</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
        </div>
      </div>
    )
  }

  const busy = saveStatus === 'saving'
  const smtpTestable = fields.enabled && fields.host.trim() !== ''

  return (
    <SectionCard title={t('adminSmtpConfigTitle')} description={t('adminSmtpConfigDesc')}>
      <form onSubmit={handleSave} className="flex flex-col gap-6">
        <AdminSmtpFields fields={fields} disabled={busy} onChange={handleChange} />

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
              disabled={!smtpTestable || busy || testStatus === 'sending'}
              onClick={handleTest}
            >
              {testStatus === 'sending'
                ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                : <Send size={13} className="mr-1.5" aria-hidden="true" />}
              {t('adminSendTestEmail')}
            </Button>
          </div>
          {!smtpTestable && (
            <p className="text-xs text-amber-700 dark:text-amber-400">
              {t('adminSmtpNotTestable')}
            </p>
          )}
        </div>

        {saveStatus === 'saved' && (
          <div className="flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
            <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
            <span className="flex-1">{saveMessage}</span>
            <button type="button" onClick={() => { if (saveTimer.current) clearTimeout(saveTimer.current); setSaveStatus('idle') }}
              className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
              <X size={13} aria-hidden="true" />
            </button>
          </div>
        )}
        {saveStatus === 'error' && (
          <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={15} className="shrink-0" aria-hidden="true" />
            <span className="flex-1">{saveMessage}</span>
            <button type="button" onClick={() => setSaveStatus('idle')}
              className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
              <X size={13} aria-hidden="true" />
            </button>
          </div>
        )}
        {testStatus === 'sent' && (
          <div className="flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
            <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
            <span className="flex-1">{testMessage}</span>
            <button type="button" onClick={() => setTestStatus('idle')}
              className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
              <X size={13} aria-hidden="true" />
            </button>
          </div>
        )}
        {testStatus === 'failed' && (
          <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={15} className="shrink-0" aria-hidden="true" />
            <span className="flex-1">{testMessage}</span>
            <button type="button" onClick={() => setTestStatus('idle')}
              className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
              <X size={13} aria-hidden="true" />
            </button>
          </div>
        )}
      </form>
    </SectionCard>
  )
}
