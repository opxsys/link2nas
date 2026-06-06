import { useState } from 'react'
import { Loader2, XCircle, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import DateTimeField from '@/components/common/DateTimeField'
import { createUser } from '@/api/admin-users'
import { useSmtpStatus } from '@/lib/useSmtpStatus'
import type { CreateUserResponse } from './admin.types'
import { useI18n } from '@/i18n'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const SELECT = INPUT
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'
const HINT = 'text-xs text-muted-foreground'

interface Props {
  onSave: (result: CreateUserResponse) => void
  onCancel: () => void
}

export default function AdminUserCreate({ onSave, onCancel }: Props) {
  const { t } = useI18n()
  const { smtpAvailable } = useSmtpStatus()
  const [mode, setMode] = useState<'password' | 'invitation'>('invitation')
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [language, setLanguage] = useState('')
  const [password, setPassword] = useState('')
  const [forcePasswordChange, setForcePasswordChange] = useState(true)
  const [validFrom, setValidFrom] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [isSuperAdmin, setIsSuperAdmin] = useState(false)
  const [emailVerified, setEmailVerified] = useState(false)
  const [canUseLocalSpace, setCanUseLocalSpace] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError('')
    try {
      const result = await createUser({
        email: email.trim().toLowerCase(),
        creation_mode: mode,
        password: mode === 'password' ? password : undefined,
        force_password_change: mode === 'password' ? forcePasswordChange : undefined,
        display_name: displayName.trim() || undefined,
        preferred_language: language || undefined,
        valid_from: validFrom || null,
        account_expires_at: expiresAt || null,
        is_super_admin: isSuperAdmin,
        email_verified: emailVerified,
        can_use_local_space: canUseLocalSpace,
      })
      onSave(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('adminUserCreateFailed'))
      setSaving(false)
    }
  }

  return (
    <SectionCard title={t('adminCreateUserTitle')}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-5">
        <div className="flex gap-4">
          {(['invitation', 'password'] as const).map((m) => (
            <label key={m} className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="radio" name="mode" value={m} checked={mode === m}
                onChange={() => setMode(m)} className={CHECK} />
              {m === 'invitation' ? t('adminInvitationLinkMode') : t('adminSetPasswordNow')}
            </label>
          ))}
        </div>

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="cu-email" className={LABEL}>{t('email')} <span className="text-destructive">*</span></label>
            <input id="cu-email" type="email" className={INPUT} value={email} disabled={saving}
              required onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <label htmlFor="cu-name" className={LABEL}>{t('labelDisplayName')} <span className={HINT}>{t('adminMaintOptional')}</span></label>
            <input id="cu-name" type="text" className={INPUT} value={displayName} disabled={saving}
              onChange={(e) => setDisplayName(e.target.value)} />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="cu-lang" className={LABEL}>{t('language')}</label>
            <select id="cu-lang" className={SELECT} value={language} disabled={saving}
              onChange={(e) => setLanguage(e.target.value)}>
              <option value="">{t('adminDefaultLang')}</option>
              <option value="en">{t('langEnglish')}</option>
              <option value="fr">{t('langFrench')}</option>
            </select>
          </div>
        </div>

        {mode === 'password' && (
          <div className="flex flex-col gap-4">
            <div>
              <label htmlFor="cu-pw" className={LABEL}>{t('password')} <span className="text-destructive">*</span></label>
              <input id="cu-pw" type="password" className={INPUT} value={password} disabled={saving}
                required autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
            </div>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" className={CHECK} checked={forcePasswordChange} disabled={saving}
                onChange={(e) => setForcePasswordChange(e.target.checked)} />
              {t('adminForcePasswordChange')}
            </label>
          </div>
        )}

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <DateTimeField id="cu-vf" label={t('adminValidFrom')} hint={t('adminMaintOptional')}
            value={validFrom} disabled={saving} onChange={setValidFrom} />
          <DateTimeField id="cu-ea" label={t('adminAccountExpires')} hint={t('adminMaintOptional')}
            value={expiresAt} disabled={saving} onChange={setExpiresAt} />
        </div>

        <div className="flex flex-wrap gap-5">
          {([
            [isSuperAdmin, setIsSuperAdmin, 'cu-super', t('adminRoleSuperAdmin')],
            [emailVerified, setEmailVerified, 'cu-verified', t('adminMarkEmailVerifiedChk')],
            [canUseLocalSpace, setCanUseLocalSpace, 'cu-space', t('adminCanUseLocalSpace')],
          ] as [boolean, (v: boolean) => void, string, string][]).map(([val, setter, id, label]) => (
            <label key={id} className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input id={id} type="checkbox" className={CHECK} checked={val} disabled={saving}
                onChange={(e) => setter(e.target.checked)} />
              {label}
            </label>
          ))}
        </div>

        {mode === 'invitation' && !smtpAvailable && (
          <p className="text-xs text-amber-700 dark:text-amber-400">
            {t('adminSmtpInviteWarning')}
          </p>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" size="sm" disabled={saving}>
            {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            {t('create')}
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={saving} onClick={onCancel}>
            {t('cancel')}
          </Button>
        </div>
        {error && (
          <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={15} className="shrink-0" aria-hidden="true" />
            <span className="flex-1">{error}</span>
            <button
              type="button"
              onClick={() => setError('')}
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
