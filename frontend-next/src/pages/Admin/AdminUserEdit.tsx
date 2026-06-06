import { useState, useEffect, useRef } from 'react'
import { Loader2, XCircle, CheckCircle2, ArrowLeft, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import DateTimeField from '@/components/common/DateTimeField'
import { updateUser, resetUserPassword } from '@/api/admin-users'
import type { RealUser, EditUserPayload } from './admin.types'
import { useI18n } from '@/i18n'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const SELECT = INPUT
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'

interface Props {
  user: RealUser
  onSave: (updated: RealUser) => void
  onCancel: () => void
}

export default function AdminUserEdit({ user, onSave, onCancel }: Props) {
  const { t } = useI18n()
  const [email, setEmail] = useState(user.email)
  const [displayName, setDisplayName] = useState(user.display_name ?? '')
  const [language, setLanguage] = useState(user.preferred_language ?? '')
  const [validFrom, setValidFrom] = useState(user.valid_from?.slice(0, 16) ?? '')
  const [expiresAt, setExpiresAt] = useState(user.account_expires_at?.slice(0, 16) ?? '')
  const [isSuperAdmin, setIsSuperAdmin] = useState(user.is_super_admin)
  const [isActive, setIsActive] = useState(user.is_active)
  const [emailVerified, setEmailVerified] = useState(user.email_verified)
  const [canUseLocalSpace, setCanUseLocalSpace] = useState(user.can_use_local_space)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')

  const [resetPw, setResetPw] = useState('')
  const [resetSaving, setResetSaving] = useState(false)
  const [resetMsg, setResetMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const resetSuccessTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    setEmail(user.email)
    setDisplayName(user.display_name ?? '')
    setLanguage(user.preferred_language ?? '')
    setValidFrom(user.valid_from?.slice(0, 16) ?? '')
    setExpiresAt(user.account_expires_at?.slice(0, 16) ?? '')
    setIsSuperAdmin(user.is_super_admin)
    setIsActive(user.is_active)
    setEmailVerified(user.email_verified)
    setCanUseLocalSpace(user.can_use_local_space)
    setSaveError('')
    setResetMsg(null)
    if (resetSuccessTimer.current) clearTimeout(resetSuccessTimer.current)
  }, [user.id]) // eslint-disable-line react-hooks/exhaustive-deps

  function buildPatch(): EditUserPayload {
    const patch: EditUserPayload = {}
    const te = email.trim().toLowerCase()
    if (te !== user.email) patch.email = te
    const tn = displayName.trim() || null
    if (tn !== user.display_name) patch.display_name = tn
    if (isSuperAdmin !== user.is_super_admin) patch.is_super_admin = isSuperAdmin
    if (isActive !== user.is_active) patch.is_active = isActive
    if (emailVerified !== user.email_verified) patch.email_verified = emailVerified
    if ((language || null) !== user.preferred_language) patch.preferred_language = language || null
    if (canUseLocalSpace !== user.can_use_local_space) patch.can_use_local_space = canUseLocalSpace
    const origVF = user.valid_from?.slice(0, 16) ?? ''
    if (validFrom !== origVF) patch.valid_from = validFrom || null
    const origEA = user.account_expires_at?.slice(0, 16) ?? ''
    if (expiresAt !== origEA) patch.account_expires_at = expiresAt || null
    return patch
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    const patch = buildPatch()
    if (Object.keys(patch).length === 0) { setSaveError(t('adminNoChanges')); return }
    setSaving(true)
    setSaveError('')
    try { onSave(await updateUser(user.id, patch)) }
    catch (err) { setSaveError(err instanceof Error ? err.message : t('saveFailed')); setSaving(false) }
  }

  async function handlePasswordReset(e: React.FormEvent) {
    e.preventDefault()
    setResetSaving(true)
    setResetMsg(null)
    try {
      await resetUserPassword(user.id, resetPw)
      setResetPw('')
      setResetMsg({ ok: true, text: t('adminPasswordResetNote') })
      resetSuccessTimer.current = setTimeout(() => setResetMsg(null), 4000)
    } catch (err) {
      setResetMsg({ ok: false, text: err instanceof Error ? err.message : t('resetFailed') })
    } finally { setResetSaving(false) }
  }

  return (
    <div className="flex flex-col gap-4">
      <Button size="sm" variant="outline" className="w-fit" onClick={onCancel}>
        <ArrowLeft size={13} className="mr-1.5" aria-hidden="true" /> {t('adminBackToUsers')}
      </Button>

      <SectionCard title={`Edit: ${user.display_name || user.email}`}>
        <form onSubmit={handleSave} className="flex flex-col gap-5">
          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="eu-email" className={LABEL}>{t('email')}</label>
              <input id="eu-email" type="email" className={INPUT} value={email} disabled={saving}
                required onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div>
              <label htmlFor="eu-name" className={LABEL}>{t('labelDisplayName')}</label>
              <input id="eu-name" type="text" className={INPUT} value={displayName} disabled={saving}
                onChange={(e) => setDisplayName(e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="eu-lang" className={LABEL}>{t('language')}</label>
              <select id="eu-lang" className={SELECT} value={language} disabled={saving}
                onChange={(e) => setLanguage(e.target.value)}>
                <option value="">{t('adminDefaultLang')}</option>
                <option value="en">{t('langEnglish')}</option>
                <option value="fr">{t('langFrench')}</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <DateTimeField id="eu-vf" label={t('adminValidFrom')} hint={t('adminClearToRemove')}
              value={validFrom} disabled={saving} onChange={setValidFrom} />
            <DateTimeField id="eu-ea" label={t('adminAccountExpires')} hint={t('adminClearToRemove')}
              value={expiresAt} disabled={saving} onChange={setExpiresAt} />
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {([
              [isSuperAdmin, setIsSuperAdmin, 'eu-super', t('adminRoleSuperAdmin')],
              [isActive, setIsActive, 'eu-active', t('adminActiveChk')],
              [emailVerified, setEmailVerified, 'eu-verified', t('adminEmailVerifiedChk')],
              [canUseLocalSpace, setCanUseLocalSpace, 'eu-space', t('adminLocalSpaceChk')],
            ] as [boolean, (v: boolean) => void, string, string][]).map(([val, setter, id, label]) => (
              <label key={id} className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
                <input id={id} type="checkbox" className={CHECK} checked={val} disabled={saving}
                  onChange={(e) => setter(e.target.checked)} />
                {label}
              </label>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" size="sm" disabled={saving}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {t('saveChanges')}
            </Button>
          </div>
          {saveError && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <XCircle size={15} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{saveError}</span>
              <button
                type="button"
                onClick={() => setSaveError('')}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
        </form>
      </SectionCard>

      <SectionCard title={t('adminResetPwSectionTitle')} description={t('adminResetPwSectionDesc')}>
        <form onSubmit={handlePasswordReset} className="flex flex-col gap-4">
          <div>
            <label htmlFor="eu-pw" className={LABEL}>{t('newPassword')} <span className="text-destructive">*</span></label>
            <input id="eu-pw" type="password" className={INPUT} value={resetPw} disabled={resetSaving}
              required autoComplete="new-password" onChange={(e) => setResetPw(e.target.value)} />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" size="sm" disabled={resetSaving || !resetPw}>
              {resetSaving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {t('adminResetPasswordBtn')}
            </Button>
          </div>
          {resetMsg && (
            <div className={`flex items-center gap-2 rounded-md border px-3 py-2.5 text-sm ${
              resetMsg.ok
                ? 'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400'
                : 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400'
            }`}>
              {resetMsg.ok
                ? <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
                : <XCircle size={15} className="shrink-0" aria-hidden="true" />}
              <span className="flex-1">{resetMsg.text}</span>
              <button
                type="button"
                onClick={() => { if (resetSuccessTimer.current) clearTimeout(resetSuccessTimer.current); setResetMsg(null) }}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
        </form>
      </SectionCard>
    </div>
  )
}
