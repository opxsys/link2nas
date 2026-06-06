import { useState, useEffect, useCallback, useRef } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { getSecuritySettings, saveSecuritySettings } from '@/api/admin-security'
import type { SecurityTokenTtl, SecurityPasswordPolicy } from './admin.types'
import AdminSecurityFields from './AdminSecurityFields'
import AdminSecurityAntiAbuse from './AdminSecurityAntiAbuse'
import { useI18n } from '@/i18n'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

const DEFAULT_TTL: SecurityTokenTtl = {
  invitation_ttl_hours: 48,
  password_reset_ttl_hours: 2,
  magic_login_ttl_minutes: 15,
  email_verification_ttl_hours: 24,
  session_inactivity_minutes: 30,
}

const DEFAULT_POLICY: SecurityPasswordPolicy = {
  min_length: 10,
  require_uppercase: false,
  require_lowercase: false,
  require_number: false,
  require_special: false,
}

export default function AdminSecurity() {
  const { t } = useI18n()
  const [tokenTtl, setTokenTtl] = useState<SecurityTokenTtl>(DEFAULT_TTL)
  const [passwordPolicy, setPasswordPolicy] = useState<SecurityPasswordPolicy>(DEFAULT_POLICY)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await getSecuritySettings()
      setTokenTtl(data.token_ttl)
      setPasswordPolicy(data.password_policy)
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : t('adminLoadSecFailed'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function handleTokenTtl(key: keyof SecurityTokenTtl, value: number) {
    setTokenTtl((p) => ({ ...p, [key]: value }))
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
  }

  function handlePasswordPolicy(key: keyof SecurityPasswordPolicy, value: boolean | number) {
    setPasswordPolicy((p) => ({ ...p, [key]: value }))
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    if (saveTimer.current) clearTimeout(saveTimer.current)
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      const updated = await saveSecuritySettings({ token_ttl: tokenTtl, password_policy: passwordPolicy })
      setTokenTtl(updated.token_ttl)
      setPasswordPolicy(updated.password_policy)
      setSaveStatus('saved')
      setSaveMessage(t('adminSecSaved'))
      saveTimer.current = setTimeout(() => setSaveStatus('idle'), 4000)
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : t('saveFailed'))
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
          <p className="font-medium">{t('adminLoadSecFailed')}</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
        </div>
      </div>
    )
  }

  const busy = saveStatus === 'saving'

  return (
    <div className="flex flex-col gap-4">
      <form onSubmit={handleSave} className="flex flex-col gap-4">
        <AdminSecurityFields
          tokenTtl={tokenTtl}
          passwordPolicy={passwordPolicy}
          disabled={busy}
          onTokenTtl={handleTokenTtl}
          onPasswordPolicy={handlePasswordPolicy}
        />

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" size="sm" disabled={busy}>
            {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            {t('adminSaveSettings')}
          </Button>
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
      </form>

      <AdminSecurityAntiAbuse />
    </div>
  )
}
