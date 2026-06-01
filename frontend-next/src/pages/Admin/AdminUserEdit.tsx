import { useState, useEffect } from 'react'
import { Loader2, XCircle, CheckCircle2, ArrowLeft } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import DateTimeField from '@/components/common/DateTimeField'
import { updateUser, resetUserPassword } from '@/api/admin-users'
import type { RealUser, EditUserPayload } from './admin.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const SELECT = INPUT
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'
const HINT = 'text-xs text-muted-foreground'

interface Props {
  user: RealUser
  onSave: (updated: RealUser) => void
  onCancel: () => void
}

export default function AdminUserEdit({ user, onSave, onCancel }: Props) {
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
    if (Object.keys(patch).length === 0) { setSaveError('No changes to save.'); return }
    setSaving(true)
    setSaveError('')
    try { onSave(await updateUser(user.id, patch)) }
    catch (err) { setSaveError(err instanceof Error ? err.message : 'Save failed.'); setSaving(false) }
  }

  async function handlePasswordReset(e: React.FormEvent) {
    e.preventDefault()
    setResetSaving(true)
    setResetMsg(null)
    try {
      await resetUserPassword(user.id, resetPw)
      setResetPw('')
      setResetMsg({ ok: true, text: 'Password reset. User must change it at next login.' })
    } catch (err) {
      setResetMsg({ ok: false, text: err instanceof Error ? err.message : 'Reset failed.' })
    } finally { setResetSaving(false) }
  }

  return (
    <div className="flex flex-col gap-4">
      <Button size="sm" variant="outline" className="w-fit" onClick={onCancel}>
        <ArrowLeft size={13} className="mr-1.5" aria-hidden="true" /> Back to users
      </Button>

      <SectionCard title={`Edit: ${user.display_name || user.email}`}>
        <form onSubmit={handleSave} className="flex flex-col gap-5">
          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="eu-email" className={LABEL}>Email</label>
              <input id="eu-email" type="email" className={INPUT} value={email} disabled={saving}
                required onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div>
              <label htmlFor="eu-name" className={LABEL}>Display name</label>
              <input id="eu-name" type="text" className={INPUT} value={displayName} disabled={saving}
                onChange={(e) => setDisplayName(e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="eu-lang" className={LABEL}>Language</label>
              <select id="eu-lang" className={SELECT} value={language} disabled={saving}
                onChange={(e) => setLanguage(e.target.value)}>
                <option value="">Default (en)</option>
                <option value="en">English</option>
                <option value="fr">Français</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <DateTimeField id="eu-vf" label="Valid from" hint="(clear to remove)"
              value={validFrom} disabled={saving} onChange={setValidFrom} />
            <DateTimeField id="eu-ea" label="Account expires" hint="(clear to remove)"
              value={expiresAt} disabled={saving} onChange={setExpiresAt} />
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {([
              [isSuperAdmin, setIsSuperAdmin, 'eu-super', 'Super admin'],
              [isActive, setIsActive, 'eu-active', 'Active'],
              [emailVerified, setEmailVerified, 'eu-verified', 'Email verified'],
              [canUseLocalSpace, setCanUseLocalSpace, 'eu-space', 'Local space'],
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
              Save changes
            </Button>
            {saveError && (
              <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
                <XCircle size={14} aria-hidden="true" /> {saveError}
              </span>
            )}
          </div>
        </form>
      </SectionCard>

      <SectionCard title="Reset Password" description="Set a temporary password. The user will be required to change it at next login.">
        <form onSubmit={handlePasswordReset} className="flex flex-col gap-4">
          <div>
            <label htmlFor="eu-pw" className={LABEL}>New password <span className="text-destructive">*</span></label>
            <input id="eu-pw" type="password" className={INPUT} value={resetPw} disabled={resetSaving}
              required autoComplete="new-password" onChange={(e) => setResetPw(e.target.value)} />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" size="sm" disabled={resetSaving || !resetPw}>
              {resetSaving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              Reset password
            </Button>
            {resetMsg && (
              <span className={`flex items-center gap-1.5 text-sm ${resetMsg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}`}>
                {resetMsg.ok ? <CheckCircle2 size={14} aria-hidden="true" /> : <XCircle size={14} aria-hidden="true" />}
                {resetMsg.text}
              </span>
            )}
          </div>
        </form>
      </SectionCard>
    </div>
  )
}
