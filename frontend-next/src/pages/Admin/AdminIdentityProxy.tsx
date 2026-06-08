import { useState, useEffect, useCallback } from 'react'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { ApiError } from '@/api/client'
import {
  getAdminIdentityProxyConfig,
  patchAdminIdentityProxyConfig,
  testAdminIdentityProxyConfig,
} from '@/api/admin-identity-proxy'
import { useI18n } from '@/i18n'
import AdminIdentityProxyInfoBlock from './AdminIdentityProxyInfoBlock'
import type { AdminIdentityProxyConfig } from './admin.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

function applyConfig(
  data: AdminIdentityProxyConfig,
  set: {
    setEnabled: (v: boolean) => void
    setLabel: (v: string) => void
    setAutoLogin: (v: boolean) => void
    setAutoCreateUsers: (v: boolean) => void
    setAllowedDomains: (v: string) => void
    setTeamDomain: (v: string) => void
    setAudience: (v: string) => void
  },
) {
  set.setEnabled(data.enabled ?? false)
  set.setLabel(data.label ?? '')
  set.setAutoLogin(data.auto_login ?? false)
  set.setAutoCreateUsers(data.auto_create_users ?? false)
  set.setAllowedDomains((data.allowed_domains ?? []).join(', '))
  const cfg = (data.config ?? {}) as Record<string, string>
  set.setTeamDomain(cfg.team_domain ?? '')
  set.setAudience(cfg.audience ?? '')
}

export default function AdminIdentityProxy() {
  const { t } = useI18n()

  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  const [enabled, setEnabled] = useState(false)
  const [label, setLabel] = useState('')
  const [autoLogin, setAutoLogin] = useState(false)
  const [autoCreateUsers, setAutoCreateUsers] = useState(false)
  const [allowedDomains, setAllowedDomains] = useState('')
  const [teamDomain, setTeamDomain] = useState('')
  const [audience, setAudience] = useState('')

  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string } | null>(null)

  const setters = { setEnabled, setLabel, setAutoLogin, setAutoCreateUsers, setAllowedDomains, setTeamDomain, setAudience }

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      applyConfig(await getAdminIdentityProxyConfig(), setters)
    } catch {
      setLoadError(t('adminIpLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

  async function handleSave() {
    setSaving(true)
    setSaveError(null)
    setSaved(false)
    setTestResult(null)
    try {
      const domains = allowedDomains.split(',').map(d => d.trim()).filter(Boolean)
      const data = await patchAdminIdentityProxyConfig({
        provider_type: 'cloudflare_access',
        enabled,
        label,
        auto_login: autoLogin,
        auto_create_users: autoCreateUsers,
        allowed_domains: domains,
        config: { team_domain: teamDomain.trim(), audience: audience.trim() },
      })
      applyConfig(data, setters)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setSaveError(t('adminIdentityProxyOidcConflict'))
      } else {
        setSaveError(err instanceof ApiError ? err.message : t('saveFailed'))
      }
    } finally {
      setSaving(false)
    }
  }

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      setTestResult(await testAdminIdentityProxyConfig())
    } catch {
      setTestResult({ ok: false, error: t('testFailed') })
    } finally {
      setTesting(false)
    }
  }

  const busy = saving || testing

  if (loading) {
    return (
      <SectionCard title={t('adminIpTitle')} description={t('adminIpDesc')}>
        <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          {t('loading')}
        </div>
      </SectionCard>
    )
  }

  if (loadError) {
    return (
      <SectionCard title={t('adminIpTitle')} description={t('adminIpDesc')}>
        <div className="flex items-center justify-between py-2">
          <p className="text-sm text-destructive">{loadError}</p>
          <Button variant="outline" size="sm" onClick={load}>{t('retry')}</Button>
        </div>
      </SectionCard>
    )
  }

  return (
    <SectionCard title={t('adminIpTitle')} description={t('adminIpDesc')}>
      <div className="flex flex-col gap-5">
        <div className="flex items-center gap-3">
          <input id="ip-enabled" type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} disabled={busy} className="mt-0.5" />
          <label htmlFor="ip-enabled" className="text-sm">{t('labelEnabled')}</label>
        </div>

        <div>
          <label htmlFor="ip-label" className={LABEL}>{t('adminIpLabel')}</label>
          <input id="ip-label" type="text" value={label} onChange={e => setLabel(e.target.value)} className={INPUT} disabled={busy} placeholder="Continue with Cloudflare Access" />
        </div>

        <div>
          <label htmlFor="ip-team-domain" className={LABEL}>{t('adminIpTeamDomain')}</label>
          <input id="ip-team-domain" type="text" value={teamDomain} onChange={e => setTeamDomain(e.target.value)} className={INPUT} disabled={busy} placeholder="yourteam.cloudflareaccess.com" />
        </div>

        <div>
          <label htmlFor="ip-audience" className={LABEL}>{t('adminIpAudience')}</label>
          <input id="ip-audience" type="text" value={audience} onChange={e => setAudience(e.target.value)} className={INPUT} disabled={busy} />
        </div>

        <div>
          <label htmlFor="ip-domains" className={LABEL}>{t('adminIpAllowedDomains')}</label>
          <input id="ip-domains" type="text" value={allowedDomains} onChange={e => setAllowedDomains(e.target.value)} className={INPUT} disabled={busy} placeholder="example.com, acme.org" />
          <p className="mt-1 text-xs text-muted-foreground">{t('adminIpAllowedDomainsHint')}</p>
        </div>

        <div className="flex items-center gap-3">
          <input id="ip-auto-login" type="checkbox" checked={autoLogin} onChange={e => setAutoLogin(e.target.checked)} disabled={busy} className="mt-0.5" />
          <label htmlFor="ip-auto-login" className="text-sm">{t('adminIpAutoLogin')}</label>
        </div>

        <div className="flex items-center gap-3">
          <input id="ip-auto-create" type="checkbox" checked={autoCreateUsers} onChange={e => setAutoCreateUsers(e.target.checked)} disabled={busy} className="mt-0.5" />
          <label htmlFor="ip-auto-create" className="text-sm">{t('adminIpAutoCreateUsers')}</label>
        </div>

        {saveError && (
          <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{saveError}</p>
        )}

        {saved && (
          <div className="flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-400">
            <CheckCircle2 size={14} aria-hidden="true" />
            {t('adminSettingsSaved')}
          </div>
        )}

        {testResult && (
          <div className={
            testResult.ok
              ? 'flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400'
              : 'flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400'
          }>
            {testResult.ok
              ? <CheckCircle2 size={14} aria-hidden="true" />
              : <XCircle size={14} aria-hidden="true" />}
            {testResult.ok ? t('adminIpTestOk') : (testResult.error ?? t('testFailed'))}
          </div>
        )}

        <AdminIdentityProxyInfoBlock />

        <div className="flex gap-2">
          <Button size="sm" onClick={handleSave} disabled={busy}>
            {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            {t('saveChanges')}
          </Button>
          <Button size="sm" variant="outline" onClick={handleTest} disabled={busy}>
            {testing && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            {t('testConnection')}
          </Button>
        </div>
      </div>
    </SectionCard>
  )
}
